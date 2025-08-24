import plotly.express as px
from pathlib import Path
import pandas as pd
import json
import matplotlib.pyplot as plt

from config import conn
from helper import log, isTableExists

COLOR_CONTINUOUS_SCALE = ["#024E1B", "#006B3E", "#FFE733", "#FFAA1C", "#FF8C01", "#ED2938"]
OUTPUT_PATH = Path("Output")

def load_data():
    """Load aggregated metrics from DB."""
    df_results = pd.read_sql_query("""
    WITH TNR AS (
        SELECT "WAF_Name",
            SUM(CASE WHEN "isBlocked" = 0 THEN 1.0 ELSE 0.0 END) / COUNT(*) * 100 AS true_negative_rate
        FROM waf_comparison
        WHERE response_status_code != 0 AND "DataSetType" = 'Legitimate'
        GROUP BY "WAF_Name"
    ),
    TPR AS (
        SELECT "WAF_Name",
            SUM(CASE WHEN "isBlocked" = 1 THEN 1.0 ELSE 0.0 END) / COUNT(*) * 100 AS true_positive_rate
        FROM waf_comparison
        WHERE response_status_code != 0 AND "DataSetType" = 'Malicious'
        GROUP BY "WAF_Name"
    ),
    ALL_WAFS AS (
        SELECT "WAF_Name" FROM TNR
        UNION
        SELECT "WAF_Name" FROM TPR
    )
    SELECT
        A."WAF_Name",
        ROUND(100 - COALESCE(TNR.true_negative_rate, 0), 3) AS false_positive_rate,
        ROUND(100 - COALESCE(TPR.true_positive_rate, 0), 3) AS false_negative_rate,
        ROUND(COALESCE(TPR.true_positive_rate, 0), 3)       AS true_positive_rate,
        ROUND(COALESCE(TNR.true_negative_rate, 0), 3)       AS true_negative_rate,
        ROUND((COALESCE(TPR.true_positive_rate, 0) + COALESCE(TNR.true_negative_rate, 0)) / 2, 3) AS balanced_accuracy
    FROM ALL_WAFS A
    LEFT JOIN TNR ON A."WAF_Name" = TNR."WAF_Name"
    LEFT JOIN TPR ON A."WAF_Name" = TPR."WAF_Name"
    ORDER BY balanced_accuracy DESC
    """, conn)


    _dff = df_results.rename({
        "WAF_Name": "WAF Name",
        "false_positive_rate": "False Positive Rate",
        "false_negative_rate": "False Negative rate",
        "true_positive_rate": "True Positive Rate",
        "true_negative_rate": "True Negative Rate",
        "balanced_accuracy": "Balanced Accuracy",
    }, axis=1).copy()

    return _dff

def create_graph(_df, metric, is_ascending):
    _df_sorted = _df.sort_values(metric, ascending=is_ascending).copy()
    fig = px.bar(
        _df_sorted,
        x=metric, y="WAF Name",
        color=metric, title=metric + " chart", text=metric,
        color_continuous_scale=COLOR_CONTINUOUS_SCALE[::-1] if is_ascending else COLOR_CONTINUOUS_SCALE,
        template='plotly', orientation='h',
    ).update_layout(title_x=0.5, font=dict(size=18))
    _df_sorted = _df_sorted[::-1]
    _df_sorted['Position'] = range(1, len(_df_sorted) + 1)
    print(f'\n\n{metric}:\n')
    print(_df_sorted[['Position', 'WAF Name', metric]].to_string(index=False))
    OUTPUT_PATH.mkdir(exist_ok=True)
    fig.write_html(OUTPUT_PATH / f"{metric}.html")

def create_2d_graph(_df):
    fig = px.scatter(
        _df,
        x='True Negative Rate',
        y='True Positive Rate',
        labels={
            "True Negative Rate": "Detection Quality (True Negative Rate)",
            "True Positive Rate": "Security Quality (True Positive Rate)"
        },
        color='Balanced Accuracy',
        title="WAF Comparison Project - Security & Detection Quality",
        text='WAF Name',
        template='plotly',
        color_continuous_scale=COLOR_CONTINUOUS_SCALE[::-1],
    ).update_layout(title_x=0.5, font=dict(size=16))
    fig.update_traces(textposition="bottom center")
    OUTPUT_PATH.mkdir(exist_ok=True)
    fig.write_html(OUTPUT_PATH / "2d Graph True Negative Rate & True Positive Rate.html")

def generate_attack_summary_table():
    df = pd.read_sql_query("SELECT * FROM waf_comparison", conn)
    df["Attack"] = df["TestName"].str.extract(r"([^/\\]+)$")
    df["Attack"] = df["Attack"].str.replace(".json", "", regex=False)
    df["Attack"] = df["Attack"].map({
        "cmdexe": "Command Execution",
        "log4shell": "Log4Shell",
        "shellshock": "Shellshock",
        "sqli": "SQL Injection",
        "traversal": "Directory Traversal",
        "xss": "Cross Site Scripting (XSS)",
        "xxe": "XML External Entity (XXE)"
    })
    summary = df.groupby(["Attack", "WAF_Name"])["isBlocked"].mean().unstack().fillna(0)
    summary *= 100
    summary = summary.round(1).sort_index()

    def highlight_block_rate(val):
        if val >= 90:
            return 'background-color: #c6efce; color: #006100'
        elif val >= 50:
            return 'background-color: #ffeb9c; color: #9c5700'
        else:
            return 'background-color: #f2dcdb; color: #9c0006'

    styled = summary.style \
        .map(highlight_block_rate) \
        .format("{:.1f}%") \
        .set_caption("WAF Block Rate (%) per Attack Type") \
        .set_table_styles([{
            'selector': 'caption',
            'props': [('caption-side', 'top'), ('font-size', '20px'), ('text-align', 'center')]
        }])

    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / "WAF_Block_Rate_Summary.html"
    styled.to_html(output_file)
    log.info(f"WAF Block Rate Summary Table saved to {output_file}")

def generate_misclassification_report():
    import html
    df = pd.read_sql_query("SELECT * FROM waf_comparison", conn)
    false_positives = df[(df["DataSetType"] == "Legitimate") & (df["isBlocked"] == 1)].copy()
    false_negatives = df[(df["DataSetType"] == "Malicious") & (df["isBlocked"] == 0)].copy()

    def prepare(df, type_label):
        df["Type"] = type_label
        df["Full URL"] = df["DestinationURL"] + df["url"]
        df["Headers"] = df["headers"].apply(json.loads).apply(json.dumps, indent=2)
        df["Data"] = df["data"].fillna("")
        df["Response Code"] = df["response_status_code"]
        df["Response Body"] = df["response_body"].str.slice(0, 1000)
        return df[[
            "Type", "WAF_Name", "method", "Full URL",
            "Headers", "Data", "Response Code", "Response Body"
        ]]

    report_df = pd.concat([
        prepare(false_positives, "False Positive"),
        prepare(false_negatives, "False Negative")
    ])

    def escape_and_pre(content):
        return f"<pre style='white-space:pre-wrap; word-wrap:break-word; max-width:600px;'>{html.escape(str(content))}</pre>"

    for col in ["Headers", "Data", "Response Body"]:
        report_df[col] = report_df[col].apply(escape_and_pre)

    styled_html = report_df.to_html(
        escape=False, index=False, classes="styled-table"
    )

    css = """
    <style>
    .styled-table { border-collapse: collapse; margin: 25px 0; font-size: 0.9em; font-family: sans-serif; width: 100%; border: 1px solid #dddddd; }
    .styled-table thead tr { background-color: #009879; color: #ffffff; text-align: left; }
    .styled-table th, .styled-table td { padding: 12px 15px; vertical-align: top; }
    .styled-table tbody tr:nth-child(even) { background-color: #f3f3f3; }
    .styled-table tbody tr:hover { background-color: #f1f1f1; }
    pre { margin: 0; font-size: 0.85em; font-family: Consolas, monospace; }
    </style>
    """

    OUTPUT_PATH.mkdir(exist_ok=True)
    output_file = OUTPUT_PATH / "Misclassifications_Report.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Misclassifications Report</title>")
        f.write(css)
        f.write("</head><body>")
        f.write("<h2 style='text-align:center;'>False Positives and False Negatives Report</h2>")
        f.write(styled_html)
        f.write("</body></html>")

def analyze_results():
    if not isTableExists('waf_comparison'):
        log.warning("Table waf_comparison doesn't exists in the DB, The analyzer was called before the runner.")
        log.warning("Please fill WAFS_DICT configuration in the config.py file and run the script again.")
        return

    OUTPUT_PATH.mkdir(exist_ok=True)
    _dff = load_data()
    create_graph(_dff, metric='False Positive Rate', is_ascending=False)
    create_graph(_dff, metric='False Negative rate', is_ascending=False)
    create_graph(_dff, metric='True Positive Rate', is_ascending=True)
    create_graph(_dff, metric='True Negative Rate', is_ascending=True)
    create_graph(_dff, metric='Balanced Accuracy', is_ascending=True)
    create_2d_graph(_dff)
    generate_attack_summary_table()
    generate_misclassification_report()
    log.info("Graph visualization saved into Output directory.")

if __name__ == '__main__':
    analyze_results()

resource "akamai_appsec_configuration" "config" {
  depends_on  = [akamai_property_activation.site_production]
  name        = "test03"
  description = "new config"
  contract_id = var.contract_id
  group_id    = var.group_id
  host_names  = [var.hostname]
}

data "akamai_appsec_configuration" "current" {
  depends_on = [akamai_appsec_configuration.config]
  name       = akamai_appsec_configuration.config.name
}

locals {
  config_id = akamai_appsec_configuration.config.config_id
}

output "config_id" {
  value = local.config_id
}

resource "akamai_appsec_match_target" "website_10289345" {
  config_id = local.config_id
  match_target = jsonencode(
    {
      "defaultFile" : "NO_MATCH",
      "filePaths" : [
        "/*"
      ],
      "hostnames" : [
        var.hostname
      ],
      "isNegativeFileExtensionMatch" : false,
      "isNegativePathMatch" : false,
      "securityPolicy" : {
        "policyId" : akamai_appsec_security_policy.test.security_policy_id
      },
      "sequence" : 0,
      "type" : "website"
    }
  )
  depends_on = [akamai_appsec_security_policy.test]
}
resource "akamai_botman_client_side_security" "client_side_security" {
  config_id = local.config_id
  client_side_security = jsonencode(
    {
      "useAllSecureTraffic" : true,
      "useSameSiteCookies" : true,
      "useStrictCspCompatibility" : false
    }
  )
}

resource "akamai_botman_transactional_endpoint_protection" "transactional_endpoint_protection" {
  config_id = local.config_id
  transactional_endpoint_protection = jsonencode(
    {
      "inlineTelemetry" : {
        "aggressiveThreshold" : 90,
        "detectionSetType" : "BOT_SCORE",
        "safeguardAction" : "USE_STRICT_ACTION",
        "strictThreshold" : 50
      },
      "sdkTelemetry" : {
        "androidAggressiveThreshold" : 90,
        "androidStrictThreshold" : 50,
        "detectionSetType" : "BOT_SCORE_SDK",
        "iosAggressiveThreshold" : 90,
        "iosStrictThreshold" : 50,
        "safeguardAction" : "USE_STRICT_ACTION"
      },
      "standardTelemetry" : {
        "aggressiveThreshold" : 90,
        "detectionSetType" : "BOT_SCORE",
        "safeguardAction" : "USE_STRICT_ACTION",
        "strictThreshold" : 50
      }
    }
  )
}

// Global Advanced
resource "akamai_appsec_advanced_settings_logging" "logging" {
  config_id = local.config_id
  logging = jsonencode(
    {
      "allowSampling" : true,
      "cookies" : {
        "type" : "all"
      },
      "customHeaders" : {
        "type" : "all"
      },
      "standardHeaders" : {
        "type" : "all"
      }
    }
  )
}

resource "akamai_appsec_advanced_settings_prefetch" "prefetch" {
  config_id            = local.config_id
  enable_app_layer     = true
  all_extensions       = false
  enable_rate_controls = false
  extensions           = ["cgi", "jsp", "aspx", "EMPTY_STRING", "php", "py", "asp"]
}

resource "akamai_appsec_advanced_settings_pragma_header" "pragma_header" {
  config_id = local.config_id
  pragma_header = jsonencode(
    {
      "action" : "REMOVE"
    }
  )
}

resource "akamai_appsec_advanced_settings_evasive_path_match" "evasive_path_match" {
  config_id         = local.config_id
  enable_path_match = true
}

resource "akamai_appsec_advanced_settings_pii_learning" "pii_learning" {
  config_id           = local.config_id
  enable_pii_learning = false
}

resource "akamai_appsec_advanced_settings_attack_payload_logging" "attack_payload_logging" {
  config_id = local.config_id
  attack_payload_logging = jsonencode(
    {
      "enabled" : true,
      "requestBody" : {
        "type" : "ATTACK_PAYLOAD"
      },
      "responseBody" : {
        "type" : "ATTACK_PAYLOAD"
      }
    }
  )
}

resource "akamai_appsec_advanced_settings_request_body" "config_settings" {
  config_id                     = local.config_id
  request_body_inspection_limit = "default"
}

// Evasive Path Match
resource "akamai_appsec_advanced_settings_evasive_path_match" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_security_policy.test.security_policy_id
  enable_path_match  = true
}

resource "akamai_botman_akamai_bot_category_action" "test_site_monitoring_and_web_development_bots_07782c03-8d21-4491-9078-b83514e6508f" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "07782c03-8d21-4491-9078-b83514e6508f"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_academic_or_research_bots_0c508e1d-73a4-4366-9e48-3c4a080f1c5d" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "0c508e1d-73a4-4366-9e48-3c4a080f1c5d"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_job_search_engine_bots_2f169206-f32c-48f7-b281-d534cf1ceeb3" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "2f169206-f32c-48f7-b281-d534cf1ceeb3"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_artificial_intelligence_ai_bots_352fca87-71ee-4b8d-ae15-d36772556072" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "352fca87-71ee-4b8d-ae15-d36772556072"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_online_advertising_bots_36b27e0c-76fc-44a4-b913-c598c5af8bba" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "36b27e0c-76fc-44a4-b913-c598c5af8bba"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_ecommerce_search_engine_bots_47bcfb70-f3f5-458b-8f7c-1773b14bc6a4" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "47bcfb70-f3f5-458b-8f7c-1773b14bc6a4"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_web_search_engine_bots_4e14219f-6568-4c9d-9bd8-b29ca2afc422" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "4e14219f-6568-4c9d-9bd8-b29ca2afc422"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_enterprise_data_aggregator_bots_50395ad2-2673-41a4-b317-9b70742fd40f" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "50395ad2-2673-41a4-b317-9b70742fd40f"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_financial_services_bots_53598904-21f5-46b1-8b51-1b991beef73b" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "53598904-21f5-46b1-8b51-1b991beef73b"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_social_media_or_blog_bots_7035af8d-148c-429a-89da-de41e68c72d8" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "7035af8d-148c-429a-89da-de41e68c72d8"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_web_archiver_bots_831ef84a-c2bb-4b0d-b90d-bcd16793b830" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "831ef84a-c2bb-4b0d-b90d-bcd16793b830"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_business_intelligence_bots_8a70d29c-a491-4583-9768-7deea2f379c1" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "8a70d29c-a491-4583-9768-7deea2f379c1"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_news_aggregator_bots_ade03247-6519-4591-8458-9b7347004b63" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "ade03247-6519-4591-8458-9b7347004b63"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_rss_feed_reader_bots_b58c9929-9fd0-45f7-86f4-1d6259285c3c" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "b58c9929-9fd0-45f7-86f4-1d6259285c3c"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_financial_account_aggregator_bots_c6692e03-d3a8-49b0-9566-5003eeaddbc1" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "c6692e03-d3a8-49b0-9566-5003eeaddbc1"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_media_or_entertainment_search_bots_dff258d5-b1ad-4bbb-b1d1-cf8e700e5bba" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "dff258d5-b1ad-4bbb-b1d1-cf8e700e5bba"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_akamai_bot_category_action" "test_seo_analytics_or_marketing_bots_f7558c03-9033-46ce-bbda-10eeda62a5d4" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  category_id        = "f7558c03-9033-46ce-bbda-10eeda62a5d4"
  akamai_bot_category_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_declared_bots_keyword_match_074df68e-fb28-432a-ac6d-7cfb958425f1" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "074df68e-fb28-432a-ac6d-7cfb958425f1"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_session_validation_1bb748e2-b3ad-41db-85fa-c69e62be59dc" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "1bb748e2-b3ad-41db-85fa-c69e62be59dc"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor",
      "sessionActivitySensitivity" : "MEDIUM"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_javascript_fingerprint_anomaly_393cba3d-656f-48f1-abe4-8dd5028c6871" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "393cba3d-656f-48f1-abe4-8dd5028c6871"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_cookie_integrity_failed_4f1fd3ea-7072-4cd0-8d12-24f275e6c75d" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "4f1fd3ea-7072-4cd0-8d12-24f275e6c75d"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_http_libraries_578dad32-024b-48b4-930c-db81831686f4" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "578dad32-024b-48b4-930c-db81831686f4"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_aggressive_web_crawlers_5bc041ad-c840-4202-9c2e-d7fc873dbeaf" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "5bc041ad-c840-4202-9c2e-d7fc873dbeaf"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_open_source_crawlersscraping_platforms_601192ae-f5e2-4a29-8f75-a0bcd3584c2b" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "601192ae-f5e2-4a29-8f75-a0bcd3584c2b"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_web_services_libraries_872ed6c2-514c-4055-9c44-9782b1c783bf" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "872ed6c2-514c-4055-9c44-9782b1c783bf"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_web_scraper_reputation_9712ab32-83bb-43ab-a46d-4c2a5a42e7e2" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "9712ab32-83bb-43ab-a46d-4c2a5a42e7e2"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor",
      "webScraperReputationSensitivity" : 4
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_browser_impersonator_a3b92f75-fa5d-436e-b066-426fc2919968" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "a3b92f75-fa5d-436e-b066-426fc2919968"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_headless_browsersautomation_tools_b88cba13-4d11-46fe-a7e0-b47e78892dc4" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "b88cba13-4d11-46fe-a7e0-b47e78892dc4"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_client_disabled_javascript_noscript_triggered_c5623efa-f326-41d1-9601-a2d201bedf63" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "c5623efa-f326-41d1-9601-a2d201bedf63"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_javascript_fingerprint_not_received_c7f70f75-e3e2-4181-8ef8-30afb6576147" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "c7f70f75-e3e2-4181-8ef8-30afb6576147"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_development_frameworks_da005ad3-8bbb-43c8-a783-d97d1fb71ad2" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "da005ad3-8bbb-43c8-a783-d97d1fb71ad2"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

resource "akamai_botman_bot_detection_action" "test_impersonators_of_known_bots_fda1ffb9-ef46-4570-929c-7449c0c750f8" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  detection_id       = "fda1ffb9-ef46-4570-929c-7449c0c750f8"
  bot_detection_action = jsonencode(
    {
      "action" : "monitor"
    }
  )
}

// IP/GEO/ASN Firewall
resource "akamai_appsec_ip_geo" "test" {
  config_id                  = local.config_id
  security_policy_id         = akamai_appsec_ip_geo_protection.test.security_policy_id
  mode                       = "block"
  ukraine_geo_control_action = "none"
}

resource "akamai_botman_javascript_injection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_botman_bot_management_settings.test.security_policy_id
  javascript_injection = jsonencode(
    {
      "injectJavaScript" : "AROUND_PROTECTED_OPERATIONS",
      "rules" : []
    }
  )
}

resource "akamai_appsec_security_policy" "test" {
  config_id              = local.config_id
  default_settings       = true
  security_policy_name   = "test"
  security_policy_prefix = "0001"
}

// Enable/Disable Protections for policy test
resource "akamai_appsec_waf_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_security_policy.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_api_constraints_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_ip_geo_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_api_constraints_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_malware_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_ip_geo_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_rate_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_malware_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_reputation_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_rate_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_appsec_slowpost_protection" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_reputation_protection.test.security_policy_id
  enabled            = true
}

resource "akamai_botman_bot_management_settings" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_slowpost_protection.test.security_policy_id
  bot_management_settings = jsonencode(
    {
      "addAkamaiBotHeader" : false,
      "enableActiveDetections" : true,
      "enableBotManagement" : true,
      "enableBrowserValidation" : false,
      "removeBotManagementCookies" : true,
      "thirdPartyProxyServiceInUse" : true
    }
  )
}

resource "akamai_appsec_rate_policy" "page_view_requests" {
  config_id = local.config_id
  rate_policy = jsonencode(
    {
      "additionalMatchOptions" : [
        {
          "positiveMatch" : false,
          "type" : "RequestMethodCondition",
          "values" : [
            "POST"
          ]
        }
      ],
      "averageThreshold" : 12,
      "burstThreshold" : 18,
      "clientIdentifiers" : [
        "ip"
      ],
      "counterType" : "per_edge",
      "description" : "A popular brute force attack that consists of sending a large number of requests for base page, HTML page or XHR requests (usually non-cacheable). This could destabilize the origin.",
      "fileExtensions" : {
        "positiveMatch" : false,
        "values" : [
          "aif",
          "aiff",
          "au",
          "avi",
          "bin",
          "bmp",
          "cab",
          "carb",
          "cct",
          "cdf",
          "class",
          "css",
          "csv",
          "dcr",
          "doc",
          "docx",
          "dtd",
          "ejs",
          "ejss",
          "eot",
          "eps",
          "exe",
          "flv",
          "gcf",
          "gff",
          "gif",
          "grv",
          "hdml",
          "hdp",
          "hqx",
          "ico",
          "ini",
          "jar",
          "jp2",
          "jpeg",
          "jpg",
          "js",
          "jxr",
          "mid",
          "midi",
          "mov",
          "mp3",
          "mp4",
          "nc",
          "ogv",
          "otc",
          "otf",
          "pct",
          "pdf",
          "pict",
          "pls",
          "png",
          "ppc",
          "ppt",
          "pptx",
          "ps",
          "pws",
          "svg",
          "svgz",
          "swa",
          "swf",
          "tif",
          "tiff",
          "ttc",
          "ttf",
          "txt",
          "vbs",
          "w32",
          "wav",
          "wbmp",
          "wdp",
          "webm",
          "webp",
          "wml",
          "wmlc",
          "wmls",
          "wmlsc",
          "woff",
          "woff2",
          "xls",
          "xlsx",
          "xsd",
          "zip"
        ]
      },
      "matchType" : "path",
      "name" : "Page View Requests",
      "pathMatchType" : "Custom",
      "pathUriPositiveMatch" : true,
      "penaltyBoxDuration" : "TEN_MINUTES",
      "requestType" : "ClientRequest",
      "sameActionOnIpv6" : true,
      "type" : "WAF",
      "useXForwardForHeaders" : false
    }
  )
}

resource "akamai_appsec_rate_policy" "origin_error" {
  config_id = local.config_id
  rate_policy = jsonencode(
    {
      "additionalMatchOptions" : [
        {
          "positiveMatch" : true,
          "type" : "ResponseStatusCondition",
          "values" : [
            "400",
            "401",
            "402",
            "403",
            "404",
            "405",
            "406",
            "407",
            "408",
            "409",
            "410",
            "500",
            "501",
            "502",
            "503",
            "504"
          ]
        }
      ],
      "averageThreshold" : 5,
      "burstThreshold" : 8,
      "clientIdentifiers" : [
        "ip"
      ],
      "counterType" : "per_edge",
      "description" : "An excessive error rate from the origin could indicate malicious activity by a bot scanning the site or a publishing error. In both cases, this would increase the origin traffic and could potentially destabilize it.",
      "matchType" : "path",
      "name" : "Origin Error",
      "pathMatchType" : "Custom",
      "pathUriPositiveMatch" : true,
      "penaltyBoxDuration" : "TEN_MINUTES",
      "requestType" : "ForwardResponse",
      "sameActionOnIpv6" : true,
      "type" : "WAF",
      "useXForwardForHeaders" : false
    }
  )
}

resource "akamai_appsec_rate_policy" "post_page_requests" {
  config_id = local.config_id
  rate_policy = jsonencode(
    {
      "additionalMatchOptions" : [
        {
          "positiveMatch" : true,
          "type" : "RequestMethodCondition",
          "values" : [
            "POST"
          ]
        }
      ],
      "averageThreshold" : 3,
      "burstThreshold" : 5,
      "clientIdentifiers" : [
        "ip"
      ],
      "counterType" : "per_edge",
      "description" : "Mitigating HTTP flood attacks using POST requests",
      "matchType" : "path",
      "name" : "POST Page Requests",
      "pathMatchType" : "Custom",
      "pathUriPositiveMatch" : true,
      "penaltyBoxDuration" : "TEN_MINUTES",
      "requestType" : "ClientRequest",
      "sameActionOnIpv6" : true,
      "type" : "WAF",
      "useXForwardForHeaders" : false
    }
  )
}

// Rate Policy Actions
resource "akamai_appsec_rate_policy_action" "test_page_view_requests" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_rate_protection.test.security_policy_id
  rate_policy_id     = akamai_appsec_rate_policy.page_view_requests.rate_policy_id
  ipv4_action        = "alert"
  ipv6_action        = "alert"
}

resource "akamai_appsec_rate_policy_action" "test_origin_error" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_rate_protection.test.security_policy_id
  rate_policy_id     = akamai_appsec_rate_policy.origin_error.rate_policy_id
  ipv4_action        = "alert"
  ipv6_action        = "alert"
}

resource "akamai_appsec_rate_policy_action" "test_post_page_requests" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_rate_protection.test.security_policy_id
  rate_policy_id     = akamai_appsec_rate_policy.post_page_requests.rate_policy_id
  ipv4_action        = "alert"
  ipv6_action        = "alert"
}

resource "akamai_appsec_reputation_profile" "web_attackers_high_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "WEBATCK",
      "name" : "Web Attackers (High Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 9
    }
  )
}

resource "akamai_appsec_reputation_profile" "dos_attackers_high_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "DOSATCK",
      "name" : "DoS Attackers (High Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 9
    }
  )
}

resource "akamai_appsec_reputation_profile" "scanning_tools_high_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "SCANTL",
      "name" : "Scanning Tools (High Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 9
    }
  )
}

resource "akamai_appsec_reputation_profile" "web_attackers_low_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "WEBATCK",
      "name" : "Web Attackers (Low Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 5
    }
  )
}

resource "akamai_appsec_reputation_profile" "dos_attackers_low_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "DOSATCK",
      "name" : "DoS Attackers (Low Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 5
    }
  )
}

resource "akamai_appsec_reputation_profile" "scanning_tools_low_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "SCANTL",
      "name" : "Scanning Tools (Low Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 5
    }
  )
}

resource "akamai_appsec_reputation_profile" "web_scrapers_low_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "WEBSCRP",
      "name" : "Web Scrapers (Low Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 5
    }
  )
}

resource "akamai_appsec_reputation_profile" "web_scrapers_high_threat" {
  config_id = local.config_id
  reputation_profile = jsonencode(
    {
      "context" : "WEBSCRP",
      "name" : "Web Scrapers (High Threat)",
      "sharedIpHandling" : "NON_SHARED",
      "threshold" : 9
    }
  )
}

resource "akamai_botman_challenge_injection_rules" "challenge_injection_rules" {
  config_id = local.config_id
  challenge_injection_rules = jsonencode(
    {
      "ajaxResubmit" : false,
      "injectJavaScript" : false
    }
  )
}

// Slow Post Protection
resource "akamai_appsec_slow_post" "test" {
  config_id                  = local.config_id
  security_policy_id         = akamai_appsec_slowpost_protection.test.security_policy_id
  slow_rate_action           = "abort"
  slow_rate_threshold_rate   = 10
  slow_rate_threshold_period = 60
}

resource "akamai_appsec_waf_mode" "test" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  mode               = "ASE_AUTO"
}

// WAF Rule Actions
// CMD Injection Attack Detected (OS Commands 4)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_950002" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950002"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (OS Commands 5)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_950006" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950006"
  rule_action        = "alert"
}

// SQL Injection Attack (Blind Testing)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_950007" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950007"
  rule_action        = "alert"
}

// Server-Side Include (SSI) Attack
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_950011" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950011"
  rule_action        = "alert"
}

// Remote File Inclusion Attack (Common PHP RFI Attacks)
resource "akamai_appsec_rule" "test_aseweb_attackrfi_950118" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950118"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Directory Traversal and Obfuscation Attempts)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_950203" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950203"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Directory Traversal and Obfuscation Attempts)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_950204" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950204"
  rule_action        = "alert"
}

// Unicode Full/Half Width Abuse Attack Attempt
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_950216" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950216"
  rule_action        = "alert"
}

// Possible URL Redirector Abuse (Off-Domain URL)
resource "akamai_appsec_rule" "test_aseweb_attackpolicy_950220" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950220"
  rule_action        = "alert"
}

// SQL Injection Attack (Tautology Probes 1)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_950902" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "950902"
  rule_action        = "alert"
}

// HTTP Response Splitting Attack (Header Injection)
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_951910" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "951910"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Fromcharcode Detected)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958003" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958003"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (HTML INPUT IMAGE Tag)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958008" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958008"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Javascript URL Protocol Handler with "lowsrc" Attribute)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958023" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958023"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Style Attribute with 'expression' Keyword)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958034" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958034"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Script Tag)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958051" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958051"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Common PoC DOM Event Triggers)
resource "akamai_appsec_rule" "test_aseweb_attackxss_958052" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "958052"
  rule_action        = "alert"
}

// SQL Injection Attack (Merge, Execute, Having Probes)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_959070" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "959070"
  rule_action        = "alert"
}

// SQL Injection Attack (Built-in Functions, Objects and Keyword Probes 1)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_959073" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "959073"
  rule_action        = "alert"
}

// PHP Injection Attack (Common Functions)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_959976" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "959976"
  rule_action        = "alert"
}

// PHP Injection Attack (Configuration Override)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_959977" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "959977"
  rule_action        = "alert"
}

// HEAD Request with Body Content
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_961011" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "961011"
  rule_action        = "alert"
}

// POST Request Missing Content-Length Header
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_961012" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "961012"
  rule_action        = "alert"
}

// Invalid HTTP Protocol Version
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_961034" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "961034"
  rule_action        = "alert"
}

// Request Containing Content, but Missing Content-Type header
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_961904" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "961904"
  rule_action        = "alert"
}

// Failed to Parse Request Body for WAF Inspection
resource "akamai_appsec_rule" "test_aseweb_attackpolicy_961912" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "961912"
  rule_action        = "alert"
}

// HTTP Range Header: Invalid Last Byte Value
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_968230" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "968230"
  rule_action        = "alert"
}

// PHP Injection Attack (Opening Tag)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_969151" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "969151"
  rule_action        = "alert"
}

// SQL Information Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970003" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970003"
  rule_action        = "alert"
}

// IIS Information Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970004" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970004"
  rule_action        = "alert"
}

// PHP Information Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970009" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970009"
  rule_action        = "alert"
}

// File or Directory Names Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970011" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970011"
  rule_action        = "alert"
}

// Directory Listing
resource "akamai_appsec_rule" "test_aseoutboundleakage_970013" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970013"
  rule_action        = "alert"
}

// ASP/JSP Source Code Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970014" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970014"
  rule_action        = "alert"
}

// PHP Source Code Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970015" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970015"
  rule_action        = "alert"
}

// Application is not Available (Server-Side Exceptions)
resource "akamai_appsec_rule" "test_aseoutbounderror_970118" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970118"
  rule_action        = "alert"
}

// Application is not Available (HTTP 5XX)
resource "akamai_appsec_rule" "test_aseoutbounderror_970901" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970901"
  rule_action        = "alert"
}

// PHP Source Code Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970902" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970902"
  rule_action        = "alert"
}

// ASP/JSP Source Code Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970903" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970903"
  rule_action        = "alert"
}

// IIS Information Leakage
resource "akamai_appsec_rule" "test_aseoutboundleakage_970904" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "970904"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (URL Protocols)
resource "akamai_appsec_rule" "test_aseweb_attackxss_973305" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "973305"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Eval/Atob Functions)
resource "akamai_appsec_rule" "test_aseweb_attackxss_973307" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "973307"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (XSS Unicode PoC String)
resource "akamai_appsec_rule" "test_aseweb_attackxss_973311" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "973311"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Common PoC Payload)
resource "akamai_appsec_rule" "test_aseweb_attackxss_973312" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "973312"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (IE XSS Filter Evasion Attempt)
resource "akamai_appsec_rule" "test_aseweb_attackxss_973335" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "973335"
  rule_action        = "alert"
}

// SQL Injection Attack (SQL Conditional Probes)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981240" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981240"
  rule_action        = "alert"
}

// SQL Injection Attack (SQL Operator and Expression Probes 1)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981242" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981242"
  rule_action        = "alert"
}

// SQL Injection Attack (SQL Operator and Expression Probes 2)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981243" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981243"
  rule_action        = "alert"
}

// SQL Injection Attack (Tautology Probes 2)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981244" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981244"
  rule_action        = "alert"
}

// SQL Injection Attack (Built-in Functions, Objects and Keyword Probes 3)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981247" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981247"
  rule_action        = "alert"
}

// SQL Injection Attack (Built-in Functions, Objects and Keyword Probes 2)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981248" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981248"
  rule_action        = "alert"
}

// SQL Injection Attack (Built-in Functions, Objects and Keyword Probes 3)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981251" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981251"
  rule_action        = "alert"
}

// SQL Injection Attack (Charset manipulation)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981252" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981252"
  rule_action        = "alert"
}

// SQL Injection Attack (Stored Procedure Detected)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981253" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981253"
  rule_action        = "alert"
}

// SQL Injection Attack (Time-based Blind Probe)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981254" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981254"
  rule_action        = "alert"
}

// SQL Injection Attack (Sysadmin access functions)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981255" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981255"
  rule_action        = "alert"
}

// SQL Injection Attack (Merge, Execute, Match Probes)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981256" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981256"
  rule_action        = "alert"
}

// SQL Injection Attack (Hex Encoding Detected)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981260" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981260"
  rule_action        = "alert"
}

// SQL Injection Attack (NoSQL MongoDB Probes)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981270" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981270"
  rule_action        = "alert"
}

// SQL Injection Attack (UNION Attempt)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981276" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981276"
  rule_action        = "alert"
}

// SQL Injection Attack (SELECT Statement Anomaly Detected)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981300" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981300"
  rule_action        = "alert"
}

// SQL Injection Attack (Known/Default DB Resources Probe)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_981320" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "981320"
  rule_action        = "alert"
}

// Security Scanner/Web Attack Tool Detected (User-Agent)
resource "akamai_appsec_rule" "test_aseweb_attacktool_999002" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "999002"
  rule_action        = "alert"
}

// Security Scanner/Web Attack Tool Detected (Request Header Names)
resource "akamai_appsec_rule" "test_aseweb_attacktool_999901" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "999901"
  rule_action        = "alert"
}

// Security Scanner/Web Attack Tool Detected (Filename)
resource "akamai_appsec_rule" "test_aseweb_attacktool_999902" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "999902"
  rule_action        = "alert"
}

// SQL Injection Attack (GROUP BY/ORDER BY)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000000" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000000"
  rule_action        = "alert"
}

// Potential Remote File Inclusion (RFI) Attack: Suspicious Off-Domain URL Reference
resource "akamai_appsec_rule" "test_aseweb_attackrfi_3000004" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000004"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (OS commands with full path)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000005" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000005"
  rule_action        = "alert"
}

// SQL Injection Attack (Comment String Termination)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000006" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000006"
  rule_action        = "alert"
}

// Command Injection (Unix File Leakage)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000007" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000007"
  rule_action        = "alert"
}

// Apache Struts Remote Command Execution (OGNL Injection)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000012" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000012"
  rule_action        = "alert"
}

// System Command Injection (Attacker Toolset Download)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000013" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000013"
  rule_action        = "alert"
}

// Apache Struts Remote Command Execution (OGNL Injection)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000014" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000014"
  rule_action        = "alert"
}

// SQL Injection Attack (Database Timing Query)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000015" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000015"
  rule_action        = "alert"
}

// MySQL Keywords Anomaly Detection Alert
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000017" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000017"
  rule_action        = "alert"
}

// SQL Injection (Built-in Functions, Objects and Keyword Probes 4)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000022" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000022"
  rule_action        = "alert"
}

// Apache Struts ClassLoader Manipulation Remote Code Execution
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000023" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000023"
  rule_action        = "alert"
}

// CVE-2014-6271 Bash Command Injection Attack
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000025" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000025"
  rule_action        = "alert"
}

// PHP Wrapper Attack
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000033" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000033"
  rule_action        = "alert"
}

// Command Injection via the Java Runtime.getRuntime() Method
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000034" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000034"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (JS On-Event Handler)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000037" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000037"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (DOM Window Properties)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000038" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000038"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (DOM Document Methods)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000039" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000039"
  rule_action        = "alert"
}

// Server Side Template Injection (SSTI)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000041" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000041"
  rule_action        = "alert"
}

// PHP Object Injection Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000056" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000056"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Common Attack Tool Keywords)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000057" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000057"
  rule_action        = "alert"
}

// Apache Struts Remote Command Execution (OGNL Injection)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000058" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000058"
  rule_action        = "alert"
}

// Cross-site Scripting Attack (Referer Header From OpenBugBounty Website)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000061" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000061"
  rule_action        = "alert"
}

// Apache Struts Remote Command Execution (Deserialization Attack)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000065" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000065"
  rule_action        = "alert"
}

// Deserialization Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000072" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000072"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Attribute Injection 1)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000080" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000080"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Attribute Injection 2)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000081" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000081"
  rule_action        = "alert"
}

// SQL Injection Attack (SmartDetect)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000100" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000100"
  rule_action        = "alert"
}

// SQL Injection Attack (Common SQL Database Probes)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000101" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000101"
  rule_action        = "alert"
}

// SQL Injection Attack (Null Byte Detected)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000102" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000102"
  rule_action        = "alert"
}

// SQL Injection Attack (NoSQL Injection)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000103" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000103"
  rule_action        = "alert"
}

// SQL Injection Attack (NoSQL Injection)
resource "akamai_appsec_rule" "test_aseweb_attacksql_injection_3000104" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000104"
  rule_action        = "alert"
}

// Pandora / DirtJumper DDoS Detection - HTTP GET Attacks
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000108" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000108"
  rule_action        = "alert"
}

// Ruby on Rails YAML Injection Attack
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000109" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000109"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (SmartDetect)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000110" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000110"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Common PoC Probes 1)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000111" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000111"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Common PoC Probes 2)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000112" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000112"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Javascript Mixed Case Obfuscation)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000113" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000113"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (Shell Script Execution)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000114" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000114"
  rule_action        = "alert"
}

// LOIC 1.1 DoS Detection
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000115" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000115"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (HTML Injection)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000116" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000116"
  rule_action        = "alert"
}

// HULK DoS Attack Tool Detected
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000117" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000117"
  rule_action        = "alert"
}

// DirtJumper DDoS Detection - HTTP POST Attacks
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000118" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000118"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (HTML Context Breaking)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000119" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000119"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Common OS Files 1)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000120" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000120"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Common OS Files 2)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000121" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000121"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Long Directory Traversal)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000122" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000122"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Directory Traversal Obfuscation)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000123" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000123"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Common OS Files 3)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000124" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000124"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Common OS Files 4)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000125" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000125"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Common OS Files 5)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000126" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000126"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (Nul Byte Detected)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000127" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000127"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack (HTML Entity Named Encoding Detected)
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000128" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000128"
  rule_action        = "alert"
}

// Pandora DDoS Detection - HTTP POST Attacks
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000129" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000129"
  rule_action        = "alert"
}

// Remote File Inclusion Attack (Well-Known RFI Testing/Attack URL)
resource "akamai_appsec_rule" "test_aseweb_attackrfi_3000130" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000130"
  rule_action        = "alert"
}

// Remote File Inclusion Attack (Well-Known RFI Filename)
resource "akamai_appsec_rule" "test_aseweb_attackrfi_3000131" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000131"
  rule_action        = "alert"
}

// Detect Attempts to Access the Wordpress Pingback API
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000132" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000132"
  rule_action        = "alert"
}

// Apache Commons FileUpload and Apache Tomcat DoS
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000133" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000133"
  rule_action        = "alert"
}

// XML External Entity (XXE) Attack
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000134" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000134"
  rule_action        = "alert"
}

// HTTP.sys Remote Code Execution Vulnerability Attack Detected (CVE-2015-1635)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000135" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000135"
  rule_action        = "alert"
}

// Potential Account Brute Force Guessing via Wordpress XML-RPC API authenticated methods
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000136" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000136"
  rule_action        = "alert"
}

// Detected LOIC / HOIC client request based on query string
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000137" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000137"
  rule_action        = "alert"
}

// Detected ARDT client request
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000138" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000138"
  rule_action        = "alert"
}

// Detect Attempts to Access the Wordpress system.multicall XML-RPC API
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000139" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000139"
  rule_action        = "alert"
}

// Avzhan Bot DDOS Detection
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000140" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000140"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (OS Commands 1)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000141" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000141"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (OS Commands 2)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000142" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000142"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Bash with -c flag)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000143" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000143"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Uname with -a flag)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000144" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000144"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Cmd.exe with "dir" command)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000145" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000145"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (/bin/sh with pipe "|")
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000146" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000146"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Shellshock Variant)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000147" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000147"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Ping Beaconing)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000148" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000148"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Common Uname PoC)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000149" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000149"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Sleep with Bracketed IFS Obfuscation)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000150" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000150"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Bracketed IFS Argument Separator Detected)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000151" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000151"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (IP Address Detected)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000152" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000152"
  rule_action        = "alert"
}

// CMD Injection Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000153" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000153"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Common PHP Function Detected)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000154" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000154"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (Php/Data Filter Detected)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000155" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000155"
  rule_action        = "alert"
}

// CMD Injection Attack Detected (PHP High-Risk Functions)
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000156" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000156"
  rule_action        = "alert"
}

// Mirai / Kaiten DDoS Detection - HTTP Attacks
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000157" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000157"
  rule_action        = "alert"
}

// Server-Side Request Forgery (SSRF) Detected (Localhost Domain Resolution)
resource "akamai_appsec_rule" "test_aseweb_attackwat_3000159" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000159"
  rule_action        = "alert"
}

// Security Scanner/Web Attack Tool Detected (PoC Testing Payload)
resource "akamai_appsec_rule" "test_aseweb_attackwat_3000160" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000160"
  rule_action        = "alert"
}

// Out-of-Band (OOB) Domain Blind Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackwat_3000161" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000161"
  rule_action        = "alert"
}

// Mirai/Kaiten Bot DDOS Detection - Bogus Search Engine Referer
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000162" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000162"
  rule_action        = "alert"
}

// Server-Side Request Forgery (SSRF) Detected (Cloud Metadata Testing)
resource "akamai_appsec_rule" "test_aseweb_attackwat_3000163" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000163"
  rule_action        = "alert"
}

// Application Layer Hash DoS Attack
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000164" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000164"
  rule_action        = "alert"
}

// Server-Side Request Forgery (SSRF) Detected (Localhost/Loopback PoC Testing)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000165" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000165"
  rule_action        = "alert"
}

// Potential Wordpress Javascript DoS Attack (CVE-2018-6389)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000166" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000166"
  rule_action        = "alert"
}

// Potential Drupal Attack (CVE-2018-7600)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000167" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000167"
  rule_action        = "alert"
}

// Edge Side Inclusion (ESI) injection Attack
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000168" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000168"
  rule_action        = "alert"
}

// Phar File Upload/Deserialization Attempt Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000169" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000169"
  rule_action        = "alert"
}

// CFM Webshell/Backdoor Upload Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000170" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000170"
  rule_action        = "alert"
}

// Webshell/Backdoor File Upload Attempt
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000171" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000171"
  rule_action        = "alert"
}

// JSP/ASP/ASPX Webshell/Backdoor Upload Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000172" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000172"
  rule_action        = "alert"
}

// Potential HTTP Desync Attack: Invalid Transfer-Encoding Header Value
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000173" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000173"
  rule_action        = "alert"
}

// Potential HTTP Desync Attack: HTTP Request Smuggling Detect in Request Body
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000174" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000174"
  rule_action        = "alert"
}

// Potential HTTP Desync Attack: Transfer-Encoding Header Name Obfuscation
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000175" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000175"
  rule_action        = "alert"
}

// Potential HTTP Desync Attack: Transfer-Encoding Header in Request Body
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000176" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000176"
  rule_action        = "alert"
}

// Potential HTTP Desync Attack: Chunked header value with invalid Header Name
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000177" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000177"
  rule_action        = "alert"
}

// Microsoft Sharepoint Remote Command Execution (Deserialization Attack)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000179" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000179"
  rule_action        = "alert"
}

// NodeJS Code Injection Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000182" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000182"
  rule_action        = "alert"
}

// Possible MS Exchange/OWA Attack Detected (CVE-2021-26855)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000183" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000183"
  rule_action        = "alert"
}

// Possible MS Exchange/OWA Attack Detected (CVE-2021-27065)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000184" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000184"
  rule_action        = "alert"
}

// Confluence/OGNLi Attack Detected (CVE-2021-26084)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000185" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000185"
  rule_action        = "alert"
}

// PowerCMS Movable Type Attack Detected (CVE-2021-20837)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000186" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000186"
  rule_action        = "alert"
}

// Magento vulnerability (Callback function) Attack Detected (CVE-2022-24086 CVE-2022-24087)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000187" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000187"
  rule_action        = "alert"
}

// Magento vulnerability (validate_rules) Attack Detected (CVE-2022-24086 CVE-2022-24087)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000188" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000188"
  rule_action        = "alert"
}

// ThinkPHP RCE (CVE-2018-20062) Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000189" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000189"
  rule_action        = "alert"
}

// XML External Entity (XXE) XInclude Attack
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000190" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000190"
  rule_action        = "alert"
}

// .NET Deserialization Attack
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000191" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000191"
  rule_action        = "alert"
}

// HTTP Hop-By-Hop Header Abuse Attack
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000192" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000192"
  rule_action        = "alert"
}

// ThinkPHP Deserialization Attack (CVE-2022-38352)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000193" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000193"
  rule_action        = "alert"
}

// Oracle ADF Faces Deserialization Attack Detected (CVE-2022-21445)
resource "akamai_appsec_rule" "test_aseweb_attackcmdi_3000195" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000195"
  rule_action        = "alert"
}

// Unix OS Command Execution
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000196" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000196"
  rule_action        = "alert"
}

// Command Injection via the ASP.NET Process.Start() Method
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000197" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000197"
  rule_action        = "alert"
}

// Possible RCE on MS Exchange Detected (CVE-2022-41040 CVE-2022-41082)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000198" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000198"
  rule_action        = "alert"
}

// Webshell Activity on Microsoft Exchange (Related to CVE-2022-41040 CVE-2022-41082)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000199" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000199"
  rule_action        = "alert"
}

// Prototype Pollution Pattern Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000200" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000200"
  rule_action        = "alert"
}

// OWASSRF CVE-2022-41080 Attack Pattern Detected (Base64 Encoded)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000202" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000202"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - String Manipulation
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000211" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000211"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Hieroglyphy/JSF*ck Obfuscation
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000212" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000212"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Common Functions
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000213" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000213"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Document Write
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000214" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000214"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - String Manipulation via Reflect
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000215" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000215"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - JS Function with Variable Assignment
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000216" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000216"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - String Manipulation with Variable Assignment
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000217" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000217"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Functions within Functions
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000218" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000218"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Obfuscation via Combined Functions
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000219" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000219"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Imported Payload
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000220" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000220"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Nested Function Calls
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000221" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000221"
  rule_action        = "alert"
}

// Cross-site Scripting (XSS) Attack - Function Invocations
resource "akamai_appsec_rule" "test_aseweb_attackxss_3000222" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000222"
  rule_action        = "alert"
}

// Python Code Injection Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000400" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000400"
  rule_action        = "alert"
}

// Null Byte in Multipart File Upload - Name or Filename
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000401" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000401"
  rule_action        = "alert"
}

// Base64-Encoded PHP Object Injection Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000403" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000403"
  rule_action        = "alert"
}

// Ruby on Rails Sensitive Operation Injection Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000404" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000404"
  rule_action        = "alert"
}

// Windows Command Injection Attack - Common Executables
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000405" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000405"
  rule_action        = "alert"
}

// Windows Command Injection Attack - Common Payloads
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000406" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000406"
  rule_action        = "alert"
}

// Linux Command Injection Attack - Common Payloads
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000407" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000407"
  rule_action        = "alert"
}

// Linux Command Injection Attack - Common Commands and Arguments
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000408" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000408"
  rule_action        = "alert"
}

// Linux Command Injection Attack - "whoami" Evasions
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000409" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000409"
  rule_action        = "alert"
}

// Linux Command Injection Attack - Common Reverse Shells and whoami Evasion
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000410" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000410"
  rule_action        = "alert"
}

// Linux Command Injection Attack - Common Command Injections with Inline Evasions
resource "akamai_appsec_rule" "test_aseweb_attackcmd_injection_3000411" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000411"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack on Linux files
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000500" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000500"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack (file://)
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000501" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000501"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - encoding evasion
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000502" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000502"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - Windows and other sensitive files
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000503" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000503"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - Null Byte in Request Path
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000504" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000504"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - %5C with Path Traversal
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000505" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000505"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - Base64 Encoded Payloads
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000506" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000506"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000507" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000507"
  rule_action        = "alert"
}

// Local File Inclusion (LFI) Attack - Linux Payloads
resource "akamai_appsec_rule" "test_aseweb_attacklfi_3000508" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000508"
  rule_action        = "alert"
}

// FiberFox DoS Attack Tool Detection
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000600" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000600"
  rule_action        = "alert"
}

// JEXBOSS Attack Tool Detection
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000601" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000601"
  rule_action        = "alert"
}

// NOWAFPLS Burp Extension Detection
resource "akamai_appsec_rule" "test_aseweb_attacktool_3000602" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000602"
  rule_action        = "alert"
}

// DDoSia Toolkit DETECTED
resource "akamai_appsec_rule" "test_aseweb_attackwat_3000603" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000603"
  rule_action        = "alert"
}

// Potential Content-Encoding Attack: Multiple Headers Detected
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000700" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000700"
  rule_action        = "alert"
}

// Invalid Expect Request Header (Potential OBS Folding Attack)
resource "akamai_appsec_rule" "test_aseweb_attackprotocol_3000701" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000701"
  rule_action        = "alert"
}

// Oracle E-Business Suite Unauthenticated RCE - CVE-2022-21587
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000901" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000901"
  rule_action        = "alert"
}

// Apache Solr SSRF Detected (CVE-2021-27905)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000902" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000902"
  rule_action        = "alert"
}

// Atlassian Confluence Hardcoded Credentials Detected (CVE-2022-26138)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000903" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000903"
  rule_action        = "alert"
}

// Apache SSRF Attack Detected (CVE-2021-40438)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000904" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000904"
  rule_action        = "alert"
}

// SAML XSLT Remote Code Execution Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000905" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000905"
  rule_action        = "alert"
}

// Coldfusion LFI Attack Detected (CVE-2023-26359)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000906" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000906"
  rule_action        = "alert"
}

// Weblogic Deserialization Attack Detected (CVE-2019-2725)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000907" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000907"
  rule_action        = "alert"
}

// ProxyToken Detected (CVE-2021-33766)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000908" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000908"
  rule_action        = "alert"
}

// FortiOS Authentication Bypass Detected (CVE-2022-40684)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000909" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000909"
  rule_action        = "alert"
}

// BitBucket Remote Code Execution Detected (CVE-2022-36804)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000910" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000910"
  rule_action        = "alert"
}

// Apache Camel Injection/Bypass (CVE-2025-27636 and CVE-2025-29891) Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000911" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000911"
  rule_action        = "alert"
}

// VMware vCenter Server UploadOVA Remote Code Execution Detected (CVE-2021-21972)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000912" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000912"
  rule_action        = "alert"
}

// PHPUnit Remote Code Execution Detected (CVE-2017-9841)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000913" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000913"
  rule_action        = "alert"
}

// Apache AirFlow Variable Import Endpoint Access (CVE-2021-38540)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000914" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000914"
  rule_action        = "alert"
}

// Apache Tomcat CGI-Servlet RCE (CVE-2019-0232)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000915" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000915"
  rule_action        = "alert"
}

// SharePoint Attribute/Property Leak Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000916" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000916"
  rule_action        = "alert"
}

// Apache APISIX Remote Code Execution Detected (CVE-2022-24112)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000917" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000917"
  rule_action        = "alert"
}

// MOVEit SQL Injection in Client Certificate Detected (CVE-2023-35708)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000918" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000918"
  rule_action        = "alert"
}

// Apache Tapestry Unauthenticated RCE Vulnerability (CVE-2021-27850)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000919" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000919"
  rule_action        = "alert"
}

// Coldfusion Deserialization Attack Detected (CVE-2023-29300)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000920" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000920"
  rule_action        = "alert"
}

// Adobe ColdFusion Access Control Bypass (CVE-2023-29298 and CVE-2023-38205)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000921" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000921"
  rule_action        = "alert"
}

// Client-Side Template Injection (CSTI) Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000922" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000922"
  rule_action        = "alert"
}

// Zimbra Directory Traversal Attack Detected (CVE-2022-27925)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000923" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000923"
  rule_action        = "alert"
}

// Citrix ShareFile Storage Zones Controller Remote Code Execution Detected (CVE-2023-24489)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000924" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000924"
  rule_action        = "alert"
}

// Confluence Privilege Escalation Vulnerability Attack Detected (CVE-2023-22515)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000925" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000925"
  rule_action        = "alert"
}

// XML External Entity (XXE) via DOCTYPE Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000926" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000926"
  rule_action        = "alert"
}

// Confluence Improper Authorization Attack Detected (CVE-2023-22518)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000927" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000927"
  rule_action        = "alert"
}

// Adobe ColdFusion WDDX Deserialization Attack Detected (CVE-2023-44350/1/3)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000928" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000928"
  rule_action        = "alert"
}

// Apache Struts Path Traversal and File Upload Attack Detected (CVE-2023-50164)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000929" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000929"
  rule_action        = "alert"
}

// Critical RCE in vCenter Server via Virtual SAN Health Check Plugin (CVE-2021-21985)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000930" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000930"
  rule_action        = "alert"
}

// Spring Framework RFD Vulnerability (CVE-2020-5421)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000931" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000931"
  rule_action        = "alert"
}

// Apache OFBiz Authentication Bypass Detected (CVE-2023-51467)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000932" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000932"
  rule_action        = "alert"
}

// Improper Access Control Vulnerability in Adobe ColdFusion (CVE-2023-26360)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000933" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000933"
  rule_action        = "alert"
}

// Ivanti Connect Secure XXE Attack Detected (CVE-2024-22024)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000934" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000934"
  rule_action        = "alert"
}

// Wordpress Brick Builder RCE Attack Detected (CVE-2024-25600)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000935" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000935"
  rule_action        = "alert"
}

// Adobe ColdFusion Arbitrary File System Read Detected (CVE-2024-20767)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000936" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000936"
  rule_action        = "alert"
}

// Spring Kafka Insecure Deserialization Detected (CVE-2023-34040)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000937" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000937"
  rule_action        = "alert"
}

// Palo Alto OS Cookie Path Traversal Detected (CVE-2024-3400)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000939" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000939"
  rule_action        = "alert"
}

// CrushFTP Server Side Template Injection Detected (CVE-2024-4040)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000940" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000940"
  rule_action        = "alert"
}

// CheckPoint Security Gateways Arbitrary File Read Detected (CVE-2024-24919)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000941" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000941"
  rule_action        = "alert"
}

// Confluence Add Language Remote Code Execution Detected (CVE-2024-21683)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000942" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000942"
  rule_action        = "alert"
}

// MinIO Information Disclosure Detected (CVE-2023-28432)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000943" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000943"
  rule_action        = "alert"
}

// JetBrains Authentication Bypass Detected (CVE-2023-42793)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000944" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000944"
  rule_action        = "alert"
}

// LikeBtn WordPress Server-Side Request Forgery Detected (CVE-2021-24150)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000945" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000945"
  rule_action        = "alert"
}

// Automation Anywhere Server-Side Request Forgery Detected (CVE-2024-6922)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000946" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000946"
  rule_action        = "alert"
}

// Apache HTTP Server Exploit Attempt Detected (CVE-2024-38475 CVE-2024-38474)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000950" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000950"
  rule_action        = "alert"
}

// Ivanti vTM Authentication Bypass Attempt Detected (CVE-2024-7593)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000951" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000951"
  rule_action        = "alert"
}

// Progress WS_FTP Ad Hoc Transfer Deserialization Attack Detected (CVE-2023-40044)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000952" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000952"
  rule_action        = "alert"
}

// Adobe ColdFusion Deserialization Attack Detected (CVE-2024-41874)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000953" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000953"
  rule_action        = "alert"
}

// elFinder LFI Base64 encoded Attack Detected (CVE-2022-26960)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000954" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000954"
  rule_action        = "alert"
}

// Cleo Products Arbitrary File Write Detected (CVE-2024-55956)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000955" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000955"
  rule_action        = "alert"
}

// Cleo Products Arbitrary File Read/Write Detected (CVE-2024-50623)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000956" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000956"
  rule_action        = "alert"
}

// Apache Tomcat Remote Code Execution Attack Detected (CVE-2025-24813)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000957" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000957"
  rule_action        = "alert"
}

// JWT Token with Algorithm 'None' Identified
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000959" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000959"
  rule_action        = "alert"
}

// CrushFTP Unauthorized Access Attempt Detected (CVE-2025-31161)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000960" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000960"
  rule_action        = "alert"
}

// Ingress NGINX RCE Detected (CVE-2025-1974)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000961" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000961"
  rule_action        = "alert"
}

// Cacti Remote Code Execution Detected (CVE-2022-46169)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000962" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000962"
  rule_action        = "alert"
}

// Joomla Information Disclosure Detected (CVE-2023-23752)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000963" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000963"
  rule_action        = "alert"
}

// HTML Injection
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000964" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000964"
  rule_action        = "alert"
}

// LDAP Injection (LDAPi) Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000965" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000965"
  rule_action        = "alert"
}

// XPATH Injection (XPATHi) Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000966" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000966"
  rule_action        = "alert"
}

// Citrix Virtual Apps and Desktops (XEN) Unauthenticated RCE (CVE-2024-8068 and CVE-2024-8069) Attack Detected
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000998" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000998"
  rule_action        = "alert"
}

// Jackson-Databind Unsafe Java Classes (Deserialization Vulnerability)
resource "akamai_appsec_rule" "test_aseweb_attackplatform_3000999" {
  config_id          = local.config_id
  security_policy_id = akamai_appsec_waf_protection.test.security_policy_id
  rule_id            = "3000999"
  rule_action        = "alert"
}


// WAF Attack Group Actions
resource "akamai_appsec_attack_group" "test_POLICY" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "POLICY"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_WAT" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "WAT"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_PROTOCOL" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "PROTOCOL"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_SQL" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "SQL"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_XSS" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "XSS"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_CMD" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "CMD"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_LFI" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "LFI"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_RFI" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "RFI"
  attack_group_action = "deny"
}

resource "akamai_appsec_attack_group" "test_PLATFORM" {
  config_id           = local.config_id
  security_policy_id  = akamai_appsec_waf_protection.test.security_policy_id
  attack_group        = "PLATFORM"
  attack_group_action = "deny"
}

resource "akamai_appsec_activations" "appsecactivation" {
  config_id           = local.config_id
  network             = var.network
  note                = var.note
  notification_emails = var.notification_emails
  version             = data.akamai_appsec_configuration.current.latest_version

  depends_on = [akamai_appsec_match_target.website_10289345]
}

data "akamai_property_rules_template" "rules" {
  template_file = abspath("${path.module}/property-snippets/main.json")

  variables {
    name  = "origin_hostname"
    value = var.origin_hostname
  }
  variables {
    name  = "forward_host_header"
    value = var.hostname
  }
  variables {
    name  = "cp_code_id"
    value = var.cp_code_id   
    type  = "number"
  }

  variables {
    name  = "server_name"
    value = var.hostname
  }
}

resource "akamai_edge_hostname" "edgekey" {
  contract_id = "ctr_${var.contract_id}"
  group_id      = var.group_id
  product_id    = "prd_Site_Accel"
  ip_behavior   = "IPV6_COMPLIANCE"
  edge_hostname = "${var.hostname}.edgekey.net"
  certificate   = akamai_cps_dv_enrollment.edge_enrollment.id
  depends_on    = [akamai_cps_dv_validation.edge_validation]
}

resource "akamai_property" "site" {
  name        = var.hostname
  contract_id = "ctr_${var.contract_id}"
  group_id    = var.group_id
  product_id  = "prd_Site_Accel"

  hostnames {
    cname_from             = var.hostname
    cname_to               = akamai_edge_hostname.edgekey.edge_hostname
    cert_provisioning_type = "CPS_MANAGED"
  }

  rule_format = "latest"
  rules       = data.akamai_property_rules_template.rules.json
  depends_on  = [akamai_edge_hostname.edgekey]
}

# NOTE: Be careful when removing this resource as you can disable traffic
resource "akamai_property_activation" "site_staging" {
  property_id                    = akamai_property.site.id
  contact                        = ["nobody@akamai.com"]
  version                        = akamai_property.site.latest_version
  network                        = "STAGING"
  auto_acknowledge_rule_warnings = true
}

# NOTE: Be careful when removing this resource as you can disable traffic
resource "akamai_property_activation" "site_production" {
  property_id                    = akamai_property.site.id
  contact                        = ["nobody@akamai.com"]
  version                        = akamai_property.site.latest_version
  network                        = "PRODUCTION"
  auto_acknowledge_rule_warnings = true
}

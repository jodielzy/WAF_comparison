resource "akamai_cps_dv_enrollment" "edge_enrollment" {
  depends_on = [null_resource.origin_cert_issue]

  common_name                 = var.hostname
  allow_duplicate_common_name = false
  sans                        = [var.origin_hostname]
  secure_network              = "enhanced-tls"
  sni_only                    = true
  acknowledge_pre_verification_warnings = false

  admin_contact {
    first_name       = "skywalker"
    last_name        = "7"
    organization     = ""
    email            = "nobody@gmail.com"
    phone            = "1111111111"
    address_line_one = ""
    city             = ""
    region           = ""
    postal_code      = ""
    country_code     = ""
  }

  certificate_chain_type = "default"

  csr {
    country_code        = "US"
    city                = "Cambridge"
    organization        = "Akamai Technologies, Inc."
    organizational_unit = ""
    state               = "MA"
  }

  network_configuration {
    disallowed_tls_versions = ["TLSv1", "TLSv1_1"]
    clone_dns_names         = true
    geography               = "core"
    must_have_ciphers       = "ak-akamai-default-2017q3"
    ocsp_stapling           = "on"
    preferred_ciphers       = "ak-akamai-default-2017q3"
  }

  signature_algorithm = "SHA-256"

  tech_contact {
    first_name       = "Leap"
    last_name        = "Dev"
    organization     = ""
    email            = "leap-dev@akamai.com"
    phone            = "617-444-3000"
    address_line_one = ""
    city             = ""
    region           = ""
    postal_code      = ""
    country_code     = ""
  }

  organization {
    name             = "Akamai Technologies, Inc."
    phone            = "617-444-3000"
    address_line_one = "150 Broadway"
    city             = "Cambridge"
    region           = "MA"
    postal_code      = "02142"
    country_code     = "US"
  }

  contract_id = "ctr_${var.contract_id}"
}

locals {
  cert_names = distinct([var.hostname, var.origin_hostname])
}

resource "time_sleep" "wait_dns" {
  depends_on      = [akamai_dns_record.acme_txt]
  create_duration = "30s"
}

resource "akamai_cps_dv_validation" "edge_validation" {
  enrollment_id = akamai_cps_dv_enrollment.edge_enrollment.id
  sans          = local.cert_names
  depends_on    = [time_sleep.wait_dns]
}

output "edge_cert_enrollment_details" {
  value = {
    enrollment_id   = akamai_cps_dv_enrollment.edge_enrollment.id
    common_name     = akamai_cps_dv_enrollment.edge_enrollment.common_name
    dns_challenges  = akamai_cps_dv_enrollment.edge_enrollment.dns_challenges
    http_challenges = akamai_cps_dv_enrollment.edge_enrollment.http_challenges
  }
}

resource "akamai_dns_record" "origin_A" {
  zone       = var.dns_zone
  name       = var.origin_hostname
  recordtype = "A"
  target     = [tolist(linode_instance.dvwa_linode1.ipv4)[0]]
  ttl        = 60
  depends_on = [linode_instance.dvwa_linode1]
}

resource "akamai_dns_record" "edge_cname" {
  zone       = var.dns_zone
  name       = var.hostname
  recordtype = "CNAME"
  target     = ["${var.hostname}.edgekey.net."]
  ttl        = 60
}

locals {
  acme_txt_records = tomap({
    for c in tolist(akamai_cps_dv_enrollment.edge_enrollment.dns_challenges) :
    trimsuffix(c.full_path, ".") => c.response_body
  })
}

resource "akamai_dns_record" "acme_txt" {
  for_each   = local.acme_txt_records
  zone       = var.dns_zone
  name       = each.key
  recordtype = "TXT"
  target     = [each.value]
  ttl        = 60
}

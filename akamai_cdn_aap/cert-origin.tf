resource "null_resource" "origin_cert_issue" {
  depends_on = [akamai_dns_record.origin_A]

  triggers = {
    fqdn       = var.origin_hostname
    expectedip = tolist(linode_instance.dvwa_linode1.ipv4)[0]
    acme_email = var.email
  }

  provisioner "remote-exec" {
    inline = [
      "FQDN='${self.triggers.fqdn}'",
      "EXPECTED='${self.triggers.expectedip}'",
      "echo \"Waiting for DNS: $FQDN → $EXPECTED\"",

      # wait up to ~6m for DNS to match
      "i=0; while [ $i -lt 36 ]; do RES=$(getent hosts \"$FQDN\" | awk '{print $1}' | head -n1 2>/dev/null || true); if [ \"$RES\" = \"$EXPECTED\" ]; then echo \"DNS OK: $RES\"; break; fi; if [ -z \"$RES\" ]; then SHOWN='<none>'; else SHOWN=\"$RES\"; fi; echo \"Got: $SHOWN (expect $EXPECTED), retry...\"; i=$((i+1)); sleep 10; done",

      # install certbot (venv) if not present
      "apt-get update",
      "apt-get install -y python3 python3-venv libaugeas-dev gcc",
      "test -d /opt/certbot || python3 -m venv /opt/certbot",
      "/opt/certbot/bin/pip install --upgrade pip",
      "/opt/certbot/bin/pip install certbot",
      "ln -sf /opt/certbot/bin/certbot /usr/bin/certbot",

      # stop DVWA (free port 80), issue cert, restart
      "docker stop dvwa || true",
      "certbot certonly --standalone -d ${self.triggers.fqdn} --agree-tos -m ${self.triggers.acme_email} --non-interactive || true",
      "[ -f /etc/letsencrypt/live/${self.triggers.fqdn}/privkey.pem ] && chmod 600 /etc/letsencrypt/live/${self.triggers.fqdn}/privkey.pem || true",
      "docker start dvwa || true"
    ]

    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(linode_instance.dvwa_linode1.ipv4)[0]
    }
  }
}

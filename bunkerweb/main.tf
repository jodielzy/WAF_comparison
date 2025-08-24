terraform {
  required_version = ">= 1.0"

  required_providers {
    linode = {
      source  = "linode/linode"
      version = "3.0.0"
    }
    akamai = {
      source  = "akamai/akamai"
      version = ">= 8.0.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.1"
    }
  }
}

provider "linode" {
  token = var.token
}

provider "akamai" {
  edgerc         = var.edgerc_path
  config_section = var.config_section
}


resource "linode_instance" "dvwa-linode2" {
  label          = "dvwa2"
  image          = "linode/ubuntu24.04"
  region         = var.region
  type           = "g6-dedicated-2"
  root_pass      = var.root_pass
  swap_size      = 1024
  private_ip     = false
  authorized_keys = [trimspace(file(var.ssh_public_key))]

  provisioner "remote-exec" {
    inline = [
      "apt update && apt install -y docker.io",
      "systemctl enable docker && systemctl start docker",
      "docker run -d -p 80:80 -v dvwa-mysql:/var/lib/mysql --name dvwa vulnerables/web-dvwa",
    ]
    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(self.ipv4)[0]
    }
  }
}

# BunkerWeb Linode
resource "linode_instance" "bunkerweb" {
  label           = "bunkerweb"
  image           = "linode/ubuntu24.04"
  region          = var.region
  type            = "g6-dedicated-2"
  root_pass       = var.root_pass
  swap_size       = 1024
  private_ip      = false
  authorized_keys = [trimspace(file(var.ssh_public_key))]

  provisioner "remote-exec" {
    inline = [
        "export DEBIAN_FRONTEND=noninteractive",
        "apt-get update",
        "apt-get install -y ca-certificates curl gnupg lsb-release",
        "install -m 0755 -d /etc/apt/keyrings",
        "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc",
        "chmod a+r /etc/apt/keyrings/docker.asc",
        "sh -c 'echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" > /etc/apt/sources.list.d/docker.list'",
        "apt-get update",
        "apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
        "systemctl enable --now docker",

        # Certbot (venv) + a DNS tool for our wait loop later
        "apt-get install -y python3 python3-dev python3-venv libaugeas-dev gcc dnsutils",
        "python3 -m venv /opt/certbot",
        "/opt/certbot/bin/pip install --upgrade pip",
        "/opt/certbot/bin/pip install certbot",
        "ln -sf /opt/certbot/bin/certbot /usr/bin/certbot",

        "mkdir -p /opt/bunkerweb"
    ]
    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(self.ipv4)[0]
    }
  }

  provisioner "file" {
    destination = "/opt/bunkerweb/docker-compose.yml"
    content = <<-YAML
      version: "3.9"

      x-bw-env: &bw-env
        API_WHITELIST_IP: "127.0.0.0/8 10.20.30.0/24"
        DATABASE_URI: "mariadb+pymysql://bunkerweb:changeme@bw-db:3306/db"

      services:
        bunkerweb:
          image: bunkerity/bunkerweb:1.6.3
          container_name: bunkerweb
          ports:
            - "80:8080/tcp"
            - "443:8443/tcp"
            - "443:8443/udp"
          environment:
            <<: *bw-env
            USE_CUSTOM_SSL: "yes"
            CUSTOM_SSL_CERT: "/etc/letsencrypt/live/${var.server_name}/fullchain.pem"
            CUSTOM_SSL_KEY:  "/etc/letsencrypt/live/${var.server_name}/privkey.pem"
            REDIRECT_HTTP_TO_HTTPS: "yes"
          restart: unless-stopped
          networks:
            - bw-universe
            - bw-services
          volumes:
            - /etc/letsencrypt:/etc/letsencrypt:ro

        bw-scheduler:
          image: bunkerity/bunkerweb-scheduler:1.6.3
          container_name: bw-scheduler
          environment:
            <<: *bw-env
            BUNKERWEB_INSTANCES: "bunkerweb"
            UI_HOST: "http://bw-ui:7000"
            MULTISITE: "yes"
            USE_REDIS: "yes"
            REDIS_HOST: "redis"

            # ---- Site configuration ----
            SERVER_NAME: "${var.server_name}"
            ${var.server_name}_IS_DRAFT: "no"
            ${var.server_name}_USE_TEMPLATE: "low"

            # Behavior / bans
            ${var.server_name}_USE_BAD_BEHAVIOR: "no"
            ${var.server_name}_BAD_BEHAVIOR_THRESHOLD: "30"
            ${var.server_name}_BAD_BEHAVIOR_BAN_TIME: "3600"

            # CORS
            ${var.server_name}_USE_CORS: "yes"
            ${var.server_name}_CORS_ALLOW_ORIGIN: "*"

            # TLS
            ${var.server_name}_USE_CUSTOM_SSL: "yes"
            ${var.server_name}_CUSTOM_SSL_CERT: "/etc/letsencrypt/live/${var.server_name}/fullchain.pem"
            ${var.server_name}_CUSTOM_SSL_KEY:  "/etc/letsencrypt/live/${var.server_name}/privkey.pem"
            ${var.server_name}_REDIRECT_HTTP_TO_HTTPS: "yes"
            ${var.server_name}_LETS_ENCRYPT_CHALLENGE: "http"

            # Policies / headers
            ${var.server_name}_USE_DNSBL: "no"
            ${var.server_name}_KEEP_UPSTREAM_HEADERS: "*"
            ${var.server_name}_CONTENT_SECURITY_POLICY: ""
            ${var.server_name}_REFERRER_POLICY: "no-referrer-when-downgrade"
            ${var.server_name}_PERMISSIONS_POLICY: ""
            ${var.server_name}_COOKIE_FLAGS: "* SameSite=Lax"

            # Limits / methods
            ${var.server_name}_USE_LIMIT_REQ: "no"
            ${var.server_name}_USE_LIMIT_CONN: "no"
            ${var.server_name}_LIMIT_CONN_MAX_HTTP1: "25"
            ${var.server_name}_LIMIT_CONN_MAX_HTTP2: "200"
            ${var.server_name}_LIMIT_CONN_MAX_HTTP3: "200"
            ${var.server_name}_LIMIT_REQ_RATE: "5r/s"
            ${var.server_name}_ALLOWED_METHODS: "GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH"
            ${var.server_name}_MAX_CLIENT_SIZE: "100m"

            # Reverse proxy to DVWA origin 
            ${var.server_name}_USE_REVERSE_PROXY: "yes"
            ${var.server_name}_REVERSE_PROXY_URL: "/"
            ${var.server_name}_REVERSE_PROXY_HOST: "http://${tolist(linode_instance.dvwa-linode2.ipv4)[0]}"
          volumes:
            - bw-storage:/data
            - /etc/letsencrypt:/etc/letsencrypt:ro
          restart: unless-stopped
          networks:
            - bw-universe
            - bw-db

        bw-ui:
          image: bunkerity/bunkerweb-ui:1.6.3
          container_name: bw-ui
          environment:
            <<: *bw-env
          restart: unless-stopped
          networks:
            - bw-universe
            - bw-db

        bw-db:
          image: mariadb:11
          container_name: bw-db
          command: --max-allowed-packet=67108864
          environment:
            MYSQL_RANDOM_ROOT_PASSWORD: "yes"
            MYSQL_DATABASE: "db"
            MYSQL_USER: "bunkerweb"
            MYSQL_PASSWORD: "changeme"
          volumes:
            - bw-data:/var/lib/mysql
          restart: unless-stopped
          networks:
            - bw-db

        redis:
          image: redis:7-alpine
          container_name: bw-redis
          command: >
            redis-server
            --maxmemory 256mb
            --maxmemory-policy allkeys-lru
            --save 60 1000
            --appendonly yes
          volumes:
            - redis-data:/data
          restart: unless-stopped
          networks:
            - bw-universe

      volumes:
        bw-data:
        bw-storage:
        redis-data:

      networks:
        bw-universe:
          name: bw-universe
          ipam:
            driver: default
            config:
              - subnet: 10.20.30.0/24
        bw-services:
          name: bw-services
        bw-db:
          name: bw-db
    YAML

    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(self.ipv4)[0]
    }
  }
}

resource "null_resource" "issue_cert_and_start_bunkerweb2" {
  depends_on = [
    linode_instance.bunkerweb,
    akamai_dns_record.bunker_A
  ]

  triggers = {
    fqdn       = var.server_name
    bunker_ip  = tolist(linode_instance.bunkerweb.ipv4)[0]
    acme_email = var.acme_email
  }

  provisioner "remote-exec" {
    inline = [
      # Set variables for the shell (no Terraform interpolation used after this)
      "FQDN='${self.triggers.fqdn}'",
      "EXPECTED='${self.triggers.bunker_ip}'",
      "echo \"Waiting for DNS: $FQDN -> $EXPECTED\"",

      # Wait up to ~6 minutes for DNS A to resolve to EXPECTED
      "i=0; while [ $i -lt 36 ]; do RES=$(getent hosts \"$FQDN\" | awk '{print $1}' | head -n1 2>/dev/null || true); if [ \"$RES\" = \"$EXPECTED\" ]; then echo \"DNS OK: $RES\"; break; fi; if [ -z \"$RES\" ]; then SHOWN='<none>'; else SHOWN=\"$RES\"; fi; echo \"Got: $SHOWN (expect $EXPECTED), retry...\"; i=$((i+1)); sleep 10; done",

      # Issue/renew cert (keep port 80 free)
      "certbot certonly --standalone -d ${self.triggers.fqdn} --agree-tos -m ${self.triggers.acme_email} --non-interactive || true",
      "[ -f /etc/letsencrypt/live/${self.triggers.fqdn}/privkey.pem ] && chmod 600 /etc/letsencrypt/live/${self.triggers.fqdn}/privkey.pem || true",

      # Start BunkerWeb stack
      "docker compose -f /opt/bunkerweb/docker-compose.yml up -d"
    ]

    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(linode_instance.bunkerweb.ipv4)[0]
    }
  }
}

resource "akamai_dns_record" "bunker_A" {
  zone       = var.zone
  name       = var.server_name
  recordtype = "A"
  target     = [tolist(linode_instance.bunkerweb.ipv4)[0]]
  ttl        = 60
}




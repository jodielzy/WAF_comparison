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
  }
}

provider "linode" {
  token = var.token
}

provider "akamai" {
  edgerc         = var.edgerc_path
  config_section = var.config_section
}

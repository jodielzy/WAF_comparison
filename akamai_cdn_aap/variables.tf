# Variables of provider file

variable "token" {
  type = string
}

variable "edgerc_path" {
  type    = string
}

variable "config_section" {
  type    = string
  default = "default"
}

# Variables of linode file

variable "root_pass" {
  type = string
}

variable "region" {
  type    = string
  default = "ap-south"
}

variable "ssh_public_key" {
  type = string
}

variable "ssh_private_key" {
  type = string
}

# Variables of dns and certificate file

variable "dns_zone" {
  type = string
}

variable "origin_hostname" {
  type = string
} 

variable "hostname" {
  type = string
}   

# Variables of cert-origin file

variable "email" {
  type = string
}

# Variables of property file

variable "cp_code_id" {
  type        = number
}

variable "contract_id" {
  type    = string
}

variable "group_id" {
  type    = string
}

# Variables of aap file

variable "network" {
  type    = string
  default = "PRODUCTION"
}

variable "note" {
  type = string
  default = ""
}

variable "notification_emails" {
  type = list(string)
  default = ["nobody@akamai.com"]
}
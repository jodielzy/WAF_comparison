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

variable "root_pass" {
  type = string
}

variable "ssh_private_key" {
  type = string
  default = "~/.ssh/id_rsa_terraform"
}

variable "ssh_public_key" {
  type = string
  default  = "~/.ssh/id_rsa_terraform.pub"
}

variable "region" {
  type    = string
  default = "ap-south"
}

variable "acme_email" {
    type = string
}

variable "server_name" {
  type        = string
}

variable "zone" {
  type        = string
}
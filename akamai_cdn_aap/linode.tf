resource "linode_instance" "dvwa_linode1" {
  label           = "dvwa1"
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
      "apt update && apt install -y docker.io",
      "systemctl enable docker && systemctl start docker",

      # Ensure DVWA only listens on loopback (Apache will be public)
      "docker rm -f dvwa 2>/dev/null || true",
      "docker run -d -p 127.0.0.1:8080:80 -v dvwa-mysql:/var/lib/mysql --name dvwa vulnerables/web-dvwa",
    ]

    connection {
      type        = "ssh"
      user        = "root"
      private_key = file(var.ssh_private_key)
      host        = tolist(self.ipv4)[0]
    }
  }
}

output "dvwa_origin_ip" {
  value = tolist(linode_instance.dvwa_linode1.ipv4)[0]
}

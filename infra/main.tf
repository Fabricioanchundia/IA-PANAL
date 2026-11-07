# Panal honeypot: one isolated EC2 instance in the default VPC.
#
# Doors:
#   - Port 22 (open to the internet): Cowrie, the fake SSH server attackers hit.
#   - Port var.admin_ssh_port (only var.admin_cidr): the real SSH server, key-only.
# Egress: only HTTP/HTTPS for OS updates and image pulls. On top of that, the host
# drops every NEW connection started by the honeypot container (see user_data).

data "aws_vpc" "default" {
  default = true
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_key_pair" "admin" {
  key_name   = "panal-admin"
  public_key = file(pathexpand(var.admin_public_key_path))
}

resource "aws_security_group" "honeypot" {
  name        = "panal-honeypot"
  description = "Panal: public SSH trap, admin SSH from one IP, minimal egress"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "trap_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Cowrie SSH honeypot, open to the internet on purpose"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Real admin SSH, only from the owner IP"
  ip_protocol       = "tcp"
  from_port         = var.admin_ssh_port
  to_port           = var.admin_ssh_port
  cidr_ipv4         = var.admin_cidr
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.honeypot.id
  description       = "OS updates and container image pulls"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "http" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Ubuntu package mirrors"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "honeypot" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.admin.key_name
  vpc_security_group_ids      = [aws_security_group.honeypot.id]
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    admin_ssh_port    = var.admin_ssh_port
    honeypot_hostname = var.honeypot_hostname
    cowrie_image      = var.cowrie_image
  })
  user_data_replace_on_change = true
  lifecycle {
    ignore_changes = [ami]
  }

  # IMDSv2 only, and hop limit 1 so containers cannot reach instance metadata.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # "standard" avoids surprise charges if CPU stays high (t3 defaults to "unlimited").
  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = {
    Name = "panal-honeypot"
  }
}

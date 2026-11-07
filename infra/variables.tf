variable "region" {
  description = "AWS region for the honeypot."
  type        = string
  default     = "us-east-2"
}

variable "aws_profile" {
  description = "AWS CLI profile with limited (EC2-only) permissions."
  type        = string
  default     = "panal"
}

variable "admin_cidr" {
  description = "Your public IP as a /32. Only this IP can reach the real admin SSH port. Set it in terraform.tfvars (gitignored)."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && endswith(var.admin_cidr, "/32")
    error_message = "admin_cidr must be a single IPv4 address in CIDR form, e.g. 203.0.113.10/32."
  }
}

variable "admin_ssh_port" {
  description = "Non-standard port for the real (admin) SSH server. Port 22 belongs to the honeypot."
  type        = number
  default     = 22222
}

variable "admin_public_key_path" {
  description = "Path to the admin SSH public key."
  type        = string
  default     = "~/.ssh/panal_admin.pub"
}

variable "instance_type" {
  description = "Small, Free plan eligible instance type."
  type        = string
  default     = "t3.micro"
}

variable "honeypot_hostname" {
  description = "Realistic hostname shown to attackers (Cowrie's default 'svr04' is a known fingerprint)."
  type        = string
  default     = "web-prod-02"
}

variable "cowrie_image" {
  description = "Cowrie container image."
  type        = string
  default     = "cowrie/cowrie:latest"
}

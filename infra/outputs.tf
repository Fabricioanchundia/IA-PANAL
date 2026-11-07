output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.honeypot.id
}

output "public_ip" {
  description = "Public IP of the honeypot (do not commit it)."
  value       = aws_instance.honeypot.public_ip
}

output "admin_ssh" {
  description = "Command to reach the real admin SSH server."
  value       = "ssh -i ~/.ssh/panal_admin -p ${var.admin_ssh_port} ubuntu@${aws_instance.honeypot.public_ip}"
}

output "api_public_ip" {
  description = "Elastic IP of the BSKG API host."
  value       = aws_eip.host.public_ip
}

output "api_url" {
  description = "Base URL of the API (HTTP unless TLS is configured)."
  value       = "http://${aws_eip.host.public_ip}:8080"
}

output "instance_id" {
  description = "EC2 instance id."
  value       = aws_instance.host.id
}

output "baseline_bucket" {
  description = "S3 bucket for the VulKG baseline (use prefix vulkg/<commit>/)."
  value       = aws_s3_bucket.baseline.bucket
}

output "data_volume_id" {
  description = "EBS data volume id (tagged bskg-backup=true)."
  value       = aws_ebs_volume.data.id
}

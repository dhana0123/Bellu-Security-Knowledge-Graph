variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "bskg"
}

variable "instance_type" {
  description = "EC2 instance type. m6i.xlarge (16 GB) recommended, m6i.large (8 GB) minimum."
  type        = string
  default     = "m6i.xlarge"
}

variable "data_volume_size_gb" {
  description = "Size of the Neo4j data volume in GB (minimum 50)."
  type        = number
  default     = 100

  validation {
    condition     = var.data_volume_size_gb >= 50
    error_message = "data_volume_size_gb must be at least 50."
  }
}

variable "root_volume_size_gb" {
  description = "Size of the encrypted root volume in GB."
  type        = number
  default     = 30
}

variable "baseline_bucket_name" {
  description = "Globally unique name of the private S3 bucket that holds the VulKG baseline files."
  type        = string
}

variable "api_allowed_cidrs" {
  description = "CIDR blocks allowed to reach the API on TCP 8080."
  type        = list(string)
}

variable "operator_cidr" {
  description = "CIDR block allowed to SSH (TCP 22)."
  type        = string
}

variable "subnet_id" {
  description = "Subnet for the instance. When null, a subnet of the default VPC is used."
  type        = string
  default     = null
}

variable "key_name" {
  description = "Name of an existing EC2 key pair for SSH access."
  type        = string
  default     = null
}

variable "repo_url" {
  description = "HTTPS git URL of the BSKG repository to clone on the host (no credentials)."
  type        = string
}

variable "repo_ref" {
  description = "Git branch or tag to check out."
  type        = string
  default     = "main"
}

variable "snapshot_retain_count" {
  description = "Number of daily EBS snapshots to retain."
  type        = number
  default     = 7
}

variable "tags" {
  description = "Extra tags applied to all resources."
  type        = map(string)
  default     = {}
}

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
  description = "EC2 arm64 instance type with at least 8 GB RAM. t4g.large (8 GB) is the default; use t4g.xlarge or m7g.xlarge (16 GB) for a larger profile."
  type        = string
  default     = "t4g.large"
  validation {
    condition     = can(regex("^(t4g\\.(large|xlarge|2xlarge)|(m6g|m7g|r6g|r7g)\\.(large|xlarge|2xlarge|4xlarge|8xlarge|12xlarge|16xlarge))$", var.instance_type))
    error_message = "instance_type must be an arm64 type with at least 8 GB RAM (t4g.large and up, or m6g, m7g, r6g, r7g from large)."
  }
}

variable "cpu_credits" {
  description = "CPU credit mode of the burstable t4g instance. unlimited avoids throttling during the long full build at extra cost; standard is cheaper but slower."
  type        = string
  default     = "unlimited"
  validation {
    condition     = contains(["unlimited", "standard"], var.cpu_credits)
    error_message = "cpu_credits must be unlimited or standard."
  }
}

variable "data_volume_size_gb" {
  description = "Size of the Neo4j data volume in GB (minimum 30, default 50)."
  type        = number
  default     = 50

  validation {
    condition     = var.data_volume_size_gb >= 30
    error_message = "data_volume_size_gb must be at least 30."
  }
}

variable "root_volume_size_gb" {
  description = "Size of the encrypted root volume in GB."
  type        = number
  default     = 30
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
  default     = 3
}

variable "tags" {
  description = "Extra tags applied to all resources."
  type        = map(string)
  default     = {}
}

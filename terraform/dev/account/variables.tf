variable "lifecycle_policy" {
  type        = string
  description = "ECR repository lifecycle policy document. Used to override the default policy."
  default     = ""
}

variable "tags" {
  type        = map(any)
  description = "Additional tags to apply."
  default     = {}
}

variable "scan_on_push" {
  type        = bool
  description = "Scan image on push to repo."
  default     = true
}

variable "allowed_read_principals" {
  type        = list(any)
  description = "External principals that are allowed to read from the ECR repository"
}

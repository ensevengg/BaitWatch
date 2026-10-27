variable "env" {
  type    = string
  default = "dev"
}

variable "db_password" {
  type      = string
  sensitive = true
}

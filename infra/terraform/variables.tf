variable "subscription_id" {
  description = "Suscripción del proyecto (sub-sspm). En CI llega por ARM_SUBSCRIPTION_ID y puede quedar en null."
  type        = string
  default     = null
}

variable "location" {
  description = "Región. westus2 queda cerca de la base de Supabase (us-west-2, Oregón)."
  type        = string
  default     = "westus2"
}

variable "owner" {
  description = "Responsable (etiqueta Owner)."
  type        = string
  default     = "miguel.ortiz.e13@gmail.com"
}

variable "api_image" {
  description = "Imagen inicial de la API. Las siguientes las despliega el CI (`az containerapp update`)."
  type        = string
  default     = "ghcr.io/juandks12/sspm-api:latest"
}

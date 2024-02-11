locals {
  public_ip = chomp(data.http.icanhazip.response_body)
}

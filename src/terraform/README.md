
## Notes

- `azapi_update_resource` provider authentication:
To get `azapi_update_resource` resource call to work, the command-line must be logged in on the target tenant/subscription. `az login` or `az login --use-device-code` must be executed to connect `az cli` to the right tenant BEFORE executing `terraform apply`.

- To successfully deploy, the terminal/CLI running terraform requires a `az login` to connect to the tenant. Probably linked to the `azapi` provider.

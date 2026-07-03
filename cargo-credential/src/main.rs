use cargo_credential::{Action, CredentialResponse, Error, RegistryInfo, Secret};

pub struct SecretServiceCredential;

impl SecretServiceCredential {
    async fn preform_future(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
    ) -> Result<CredentialResponse, Error> {
        let service = oo7::dbus::Service::new()
            .await
            .map_err(|err| Error::Other(Box::new(err)))?;
        let collection = service
            .default_collection()
            .await
            .map_err(|err| Error::Other(Box::new(err)))?;
        let attributes = &[("url", registry.index_url)];
        let items = collection
            .search_items(attributes)
            .await
            .map_err(|err| Error::Other(Box::new(err)))?;

        match action {
            cargo_credential::Action::Get(_) => {
                if items.is_empty() {
                    return Err(Error::NotFound);
                }

                let secret = items[0]
                    .secret()
                    .await
                    .map_err(|err| Error::Other(Box::new(err)))?;
                let token = Secret::from(
                    secret
                        .as_str()
                        .ok_or_else(|| Error::Other("secret is not valid UTF-8".into()))?
                        .to_owned(),
                );

                Ok(CredentialResponse::Get {
                    token,
                    cache: cargo_credential::CacheControl::Session,
                    operation_independent: true,
                })
            }
            cargo_credential::Action::Login(options) => {
                let token = cargo_credential::read_token(options, registry)?.expose();

                if let Some(item) = items.first() {
                    item.set_secret(token)
                        .await
                        .map_err(|err| Error::Other(Box::new(err)))?;
                } else {
                    collection
                        .create_item(
                            &format!("cargo-registry:{}", registry.index_url),
                            attributes,
                            token,
                            true,
                            None,
                        )
                        .await
                        .map_err(|err| Error::Other(Box::new(err)))?;
                }

                Ok(CredentialResponse::Login)
            }
            cargo_credential::Action::Logout => {
                if items.is_empty() {
                    return Err(Error::NotFound);
                }

                items[0]
                    .delete(None)
                    .await
                    .map_err(|err| Error::Other(Box::new(err)))?;
                Ok(CredentialResponse::Logout)
            }
            _ => Err(Error::OperationNotSupported),
        }
    }
}

impl cargo_credential::Credential for SecretServiceCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        _args: &[&str],
    ) -> Result<CredentialResponse, Error> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { self.preform_future(registry, action).await })
    }
}

fn main() {
    cargo_credential::main(SecretServiceCredential {});
}

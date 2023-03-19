use super::super::models::generate_account::Account;
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use stellar_strkey::ed25519::{PrivateKey, PublicKey};
pub struct AccountService {}

impl AccountService {
    pub async fn generate_new_account() -> Result<Account, reqwest::Error> {
        let mut cspng = OsRng {};
        let kp: Keypair = Keypair::generate(&mut cspng);
        let private = PrivateKey(kp.secret.to_bytes());
        let public = PublicKey(kp.public.to_bytes());
        let result = call_friend_bot(public.to_string()).await?;
        Ok(Account::new(
            public.to_string(),
            private.to_string(),
            Some(result),
        ))
    }
}

async fn call_friend_bot(public_address: String) -> Result<serde_json::Value, reqwest::Error> {
    let body = reqwest::get(format!(
        "https://friendbot-futurenet.stellar.org?addr={}",
        public_address.to_string()
    ))
    .await?
    .json::<serde_json::Value>()
    .await?;
    Ok(body)
}

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct GenerateAccountRequest {
    username: String,
}

#[derive(Serialize)]
pub struct GenerateAccountResponse {
    username: String,
    res: serde_json::Value,
    private_key: String,
    public_key: String,
}

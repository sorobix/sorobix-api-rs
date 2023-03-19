use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct GenerateAccountRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct GenerateAccountResponse {
    pub username: String,
    pub res: serde_json::Value,
    pub private_key: String,
    pub public_key: String,
}

pub struct Account {
    pub public: String,
    pub private: String,
    pub result: Option<serde_json::Value>,
}

impl Account {
    pub fn new(public: String, private: String, result: Option<serde_json::Value>) -> Account {
        Account {
            public,
            private,
            result,
        }
    }
}

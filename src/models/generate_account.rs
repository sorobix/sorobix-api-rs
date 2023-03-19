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

pub struct Account {
    public: String,
    private: String,
    result: Option<serde_json::Value>,
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

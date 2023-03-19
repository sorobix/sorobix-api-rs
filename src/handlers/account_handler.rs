use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::models::{
    generate_account::{GenerateAccountRequest, GenerateAccountResponse},
    response::{Response, ResponseEnum},
    router_state::RouterState,
};

pub async fn generate_new_account(
    State(state): State<Arc<RouterState>>,
    Json(payload): Json<GenerateAccountRequest>,
) -> (StatusCode, Json<Response>) {
    let account = state
        .application_service
        .get_account_service()
        .generate_new_account()
        .await;
    match account {
        Ok(data) => {
            let account_response = GenerateAccountResponse {
                username: payload.username,
                res: data.result.unwrap_or_default(),
                private_key: data.private,
                public_key: data.public,
            };
            let response = Response::success_response(
                "account generated succesfully!".to_string(),
                ResponseEnum::GenerateAccountResponse(account_response),
            );
            (StatusCode::CREATED, Json(response))
        }
        Err(error) => {
            let response = Response::fail_response(error.to_string());
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

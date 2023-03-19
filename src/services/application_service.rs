use super::account_service::AccountService;

pub struct ApplicationService {
    account_service: AccountService,
}

impl ApplicationService {
    pub fn new() -> ApplicationService {
        ApplicationService {
            account_service: AccountService {},
        }
    }
}

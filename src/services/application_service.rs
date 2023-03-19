use super::account_service::AccountService;

pub struct ApplicationService {
    pub account_service: AccountService,
}

impl ApplicationService {
    pub fn new() -> ApplicationService {
        ApplicationService {
            account_service: AccountService {},
        }
    }
    pub fn get_account_service(&self) -> &AccountService {
        &self.account_service
    }
}

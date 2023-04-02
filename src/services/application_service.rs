use super::account_service::AccountService;
use super::contract_service::ContractService;

pub struct ApplicationService {
    pub account_service: AccountService,
    pub contract_service: ContractService,
}

impl ApplicationService {
    pub fn new() -> ApplicationService {
        ApplicationService {
            account_service: AccountService {},
            contract_service: ContractService {},
        }
    }
    pub fn get_account_service(&self) -> &AccountService {
        &self.account_service
    }
    pub fn get_contract_service(&self) -> &ContractService {
        &self.contract_service
    }
}

use super::account_service::AccountService;
use super::contract_deployer::ContractDepoymentService;
use super::contract_service::ContractService;

pub struct ApplicationService {
    pub account_service: AccountService,
    pub contract_service: ContractService,
    pub contract_deployment_service: ContractDepoymentService,
    pub redis: redis::Client,
}

impl ApplicationService {
    pub fn new(r: redis::Client) -> ApplicationService {
        ApplicationService {
            account_service: AccountService {},
            contract_service: ContractService {},
            contract_deployment_service: ContractDepoymentService {},
            redis: r,
        }
    }
    pub fn get_account_service(&self) -> &AccountService {
        &self.account_service
    }
    pub fn get_contract_service(&self) -> &ContractService {
        &self.contract_service
    }
    pub fn get_contract_deployment_service(&self) -> &ContractDepoymentService {
        &self.contract_deployment_service
    }
}

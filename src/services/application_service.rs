use super::account_service::AccountService;
use super::contract_deployer::ContractDepoymentService;
use super::contract_invoker::ContractInvokerService;

pub struct ApplicationService {
    pub account_service: AccountService,
    pub contract_deployment_service: ContractDepoymentService,
    pub contract_invoker_service: ContractInvokerService,
    pub redis: redis::Client,
}

impl ApplicationService {
    pub fn new(r: redis::Client) -> ApplicationService {
        ApplicationService {
            account_service: AccountService {},
            contract_deployment_service: ContractDepoymentService {},
            contract_invoker_service: ContractInvokerService {},
            redis: r,
        }
    }
    pub fn get_account_service(&self) -> &AccountService {
        &self.account_service
    }
    pub fn get_contract_deployment_service(&self) -> &ContractDepoymentService {
        &self.contract_deployment_service
    }
}

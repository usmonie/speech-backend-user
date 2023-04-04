use std::future::{Future, ready};
use std::sync::Arc;
use std::task::Poll::Ready;
use std::task::ready;
use async_trait::async_trait;

use speech_backend_common::{API_ERROR_NOT_FOUND_CODE, ApiError, ApiResult};
use speech_backend_common::domain::UseCase;
use speech_backend_sessions::models::request::{AddUserToSessionRequest, GetSessionRequest, UpdateSessionIpRequest};
use speech_backend_sessions::models::results::Session;
use tokio::join;

use tokio::sync::Mutex;

use crate::data::UsersRepository;
use crate::models::request::{CheckIsUsernameAvailableRequest, CheckPasswordRequest, CreateUserRequest, SearchUserByUsernameRequest, UpdatePasswordRequest};
use crate::models::results::User;

pub struct CreateUserUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    update_session_ip_use_case: Arc<Mutex<dyn UseCase<UpdateSessionIpRequest, Session> + Send + Sync>>,
    add_user_to_session_use_case: Arc<Mutex<dyn UseCase<AddUserToSessionRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<CreateUserRequest, User> for CreateUserUseCase {
    async fn execute(&self, request: CreateUserRequest) -> ApiResult<User> {
        let session = async {
            self.get_session_use_case
                .lock()
                .await
                .execute(GetSessionRequest { id: request.session_id.to_string() })
                .await
        };

        let user_result = self.user_repository.lock().await
            .store_user(
                request.name,
                request.about,
                request.username,
                request.avatar,
                request.two_factor_auth_code,
                request.email,
            ).await;

        match &user_result {
            ApiResult::Ok(user) => {
                self.add_user_to_session_use_case.lock()
                    .await
                    .execute(AddUserToSessionRequest {
                        session_id: request.session_id,
                        latest_ip_address: request.ip_address,
                        user_id: user.id,
                        session_key: session.session_key,
                        user_password_hash: request.user_password_hash,
                    }).await;

                user_result
            }
            ApiResult::Err(_) => user_result
        }
    }
}

pub struct CheckIsUsernameAvailableUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    update_session_ip_use_case: Arc<Mutex<dyn UseCase<UpdateSessionIpRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<CheckIsUsernameAvailableRequest, bool> for CheckIsUsernameAvailableUseCase {
    async fn execute(&self, request: CheckIsUsernameAvailableRequest) -> ApiResult<bool> {
        {
            let session: ApiResult<Session> = self.get_session_use_case
                .lock()
                .await
                .execute(GetSessionRequest { id: request.session_id.to_string() })
                .await;

            match session {
                ApiResult::Ok(session) => {
                    self.update_session_ip_use_case.lock().await
                        .execute(UpdateSessionIpRequest {
                            session_id: session.id.parse().unwrap(),
                            latest_ip_address: request.ip_addr,
                            session_key: session.session_key,
                        }).await;
                }
                ApiResult::Err(error) => return ApiResult::Err(error)
            };
        }

        let user_result = self.user_repository.lock().await
            .get_user_by_username(request.username.as_str())
            .await;

        match user_result {
            ApiResult::Ok(user) => ApiResult::Ok(user.username == request.username),
            ApiResult::Err(err) => {
                if err.code == API_ERROR_NOT_FOUND_CODE { ApiResult::Ok(false) } else { ApiResult::Err(err) }
            }
        }
    }
}

pub struct CheckPasswordUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    update_session_ip_use_case: Arc<Mutex<dyn UseCase<UpdateSessionIpRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<CheckPasswordRequest, bool> for CheckPasswordUseCase {
    async fn execute(&self, request: CheckPasswordRequest) -> ApiResult<bool> {
        {
            let session: ApiResult<Session> = self.get_session_use_case
                .lock()
                .await
                .execute(GetSessionRequest { id: request.session_id.to_string() })
                .await;

            match session {
                ApiResult::Ok(_) => {}
                ApiResult::Err(error) => return ApiResult::Err(error)
            };
        }

        let repository = self.user_repository.lock().await;
        let password_hash_result = repository
            .get_user_password_hash(request.user_id.as_str())
            .await;

        let password_salt_result = repository
            .get_user_password_salt(request.user_id.as_str())
            .await;

        match (&password_salt_result, &password_hash_result) {
            (ApiResult::Ok(salt), ApiResult::Ok(hash)) => {
                ApiResult::Ok(
                    enigma::verify_password(
                        hash,
                        &*request.user_password,
                        salt,
                        &*request.password_pepper,
                    )
                )
            }
            (_, _) => ApiResult::Err(ApiError::not_found("Password not found".to_string())),
        }
    }
}

pub struct UpdatePasswordUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    check_password_use_case: Arc<Mutex<dyn UseCase<CheckPasswordRequest, bool> + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    update_session_ip_use_case: Arc<Mutex<dyn UseCase<UpdateSessionIpRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<UpdatePasswordRequest, bool> for UpdatePasswordUseCase {
    async fn execute(&self, request: UpdatePasswordRequest) -> ApiResult<bool> {
        {
            let session: ApiResult<Session> = self.get_session_use_case
                .lock()
                .await
                .execute(GetSessionRequest { id: request.session_id.to_string() })
                .await;

            match session {
                ApiResult::Ok(_) => {}
                ApiResult::Err(error) => return ApiResult::Err(error)
            };
        }
        let mut repository = self.user_repository.lock().await;

        let is_password_valid = self.check_password_use_case.lock().await
            .execute(CheckPasswordRequest {
                session_id: request.session_id.clone(),
                user_id: request.user_id.clone(),
                user_password: request.previous_password.clone(),
                password_pepper: request.password_pepper.clone(),
            }).await;

        // match is_password_valid {
        //     ApiResult::Ok(_) => {}
        //     ApiResult::Err(_) => {}
        // }

        if is_password_valid.is_ok() {
            let new_password_hash = enigma::encrypt_password(
                &*request.new_user_password,
                &*request.password_salt,
                &request.password_pepper,
            );
            repository.store_user_password_hash(
                &request.user_id,
                new_password_hash.to_vec(),
                request.password_salt,
            );
        }

        todo!()
        //
        // ApiResult::Ok(is_password_valid)
    }
}

pub struct SearchUserByUsernameUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    update_session_ip_use_case: Arc<Mutex<dyn UseCase<UpdateSessionIpRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<SearchUserByUsernameRequest, User> for SearchUserByUsernameUseCase {
    async fn execute(&self, request: SearchUserByUsernameRequest) -> ApiResult<User> {
        {
            let session: ApiResult<Session> = self.get_session_use_case
                .lock()
                .await
                .execute(GetSessionRequest { id: request.session_id.to_string() })
                .await;

            match session {
                ApiResult::Ok(_) => {}
                ApiResult::Err(error) => return ApiResult::Err(error)
            };
        }

        todo!()
    }
}
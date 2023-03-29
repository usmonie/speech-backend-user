use std::str::FromStr;
use std::sync::Arc;

use speech_backend_common::ApiResult;
use speech_backend_common::domain::UseCase;
use speech_backend_sessions::models::request::{AddUserToSessionRequest, GetSessionRequest};
use speech_backend_sessions::models::results::Session;

use tokio::sync::Mutex;
use uuid::Uuid;

use crate::data::UsersRepository;
use crate::models::request::{CheckIsUsernameAvailableRequest, CreateUserRequest};
use crate::models::results::User;
use crate::models::User;

pub struct CreateUserUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
    get_session_use_case: Arc<Mutex<dyn UseCase<GetSessionRequest, Session> + Send + Sync>>,
    add_user_to_session_use_case: Arc<Mutex<dyn UseCase<AddUserToSessionRequest, Session> + Send + Sync>>,
}

#[async_trait]
impl UseCase<CreateUserRequest, User> for CreateUserUseCase {
    async fn execute(&self, request: CreateUserRequest) -> ApiResult<User> {
        let session: ApiResult<Session> = self.get_session_use_case.lock()
            .await
            .execute(GetSessionRequest { id: request.session_id.to_string() })
            .await;

        let session = match session {
            ApiResult::Ok(session) => session,
            ApiResult::Err(error) => return ApiResult::Err(*error)
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
            ApiResult::Err(err) => user_result
        }
    }
}

pub struct CheckIsUsernameAvailableUseCase {
    user_repository: Arc<Mutex<dyn UsersRepository + Send + Sync>>,
}

#[async_trait]
impl UseCase<CheckIsUsernameAvailableRequest, bool> for CheckIsUsernameAvailableUseCase {
    async fn execute(&self, request: CheckIsUsernameAvailableRequest) -> ApiResult<bool> {
        let user_result = self.user_repository.lock().await
            .get_user_by_username(request.username.as_str())
            .await;

        match user_result {
            ApiResult::Ok(user) => ApiResult::Ok(user.username == request.username),
            ApiResult::Err(_) => ApiResult::Ok(false)
        }
    }
}
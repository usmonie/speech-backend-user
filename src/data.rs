use speech_backend_common::ApiResult;
use speech_backend_common::data::DataHolder;
use uuid::Uuid;
use crate::models::results::User;
use crate::models::User;

#[async_trait]
pub trait UsersRepository {
    async fn store_user(
        &self,
        name: String,
        about: Option<String>,
        username: String,
        avatar: Option<String>,
        two_factor_auth_code: String,
        email: String
    ) -> ApiResult<User>;

    async fn update_user(&self, user: User) -> ApiResult<User>;

    async fn store_user_password_hash(&self, user_id: &str, hash: Vec<u8>, salt: Vec<u8>);

    async fn get_user_password_hash(&self, user_id: &str) -> ApiResult<Vec<u8>>;
    async fn get_user_password_salt(&self, user_id: &str) -> ApiResult<Vec<u8>>;

    async fn get_user_by_id(&self, id: &str) -> ApiResult<User>;
    async fn get_user_by_username(&self, username: &str) -> ApiResult<User>;

    async fn search_users_by_username(&self, username: &str) -> ApiResult<Vec<User>>;
}

impl UsersRepository for DataHolder {
    async fn store_user(&self, name: String, about: Option<String>, username: String, avatar: Option<String>, two_factor_auth_code: String, email: String) -> ApiResult<User> {
        todo!()
    }

    async fn update_user(&self, user: User) -> ApiResult<User> {
        todo!()
    }

    async fn store_user_password_hash(&self, user_id: &str, hash: Vec<u8>, salt: Vec<u8>) {
        todo!()
    }

    async fn get_user_password_hash(&self, user_id: &str) -> ApiResult<Vec<u8>> {
        todo!()
    }

    async fn get_user_password_salt(&self, user_id: &str) -> ApiResult<Vec<u8>> {
        todo!()
    }

    async fn get_user_by_id(&self, id: &str) -> ApiResult<User> {
        todo!()
    }

    async fn get_user_by_username(&self, username: &str) -> ApiResult<User> {
        todo!()
    }

    async fn search_users_by_username(&self, username: &str) -> ApiResult<Vec<User>> {
        todo!()
    }
}
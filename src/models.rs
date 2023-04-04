pub mod results {
    use speech_backend_media::models::result::GraphicMedia;
    use uuid::Uuid;

    pub struct User {
        pub id: Uuid,

        pub name: String,
        pub about: Option<String>,

        pub username: String,
        pub avatar: Option<GraphicMedia>,

        pub two_factor_auth_code: String,
        pub email: String,

        pub created_at: u128,
        pub last_seen_at: u128,
    }
}

pub mod request {
    use std::net::IpAddr;
    use uuid::Uuid;

    pub struct CreateUserRequest {
        pub session_id: Uuid,
        pub ip_address: IpAddr,
        pub user_password_hash: Vec<u8>,

        pub name: String,
        pub about: Option<String>,

        pub username: String,
        pub avatar: Option<String>,

        pub two_factor_auth_code: String,
        pub email: String,
    }

    pub struct CheckIsUsernameAvailableRequest {
        pub session_id: String,
        pub username: String,
        pub ip_addr: IpAddr
    }

    pub struct CheckPasswordRequest {
        pub session_id: String,
        pub user_id: String,
        pub user_password: Vec<u8>,
        pub password_pepper: Vec<u8>
    }

    pub struct UpdatePasswordRequest {
        pub session_id: String,
        pub user_id: String,
        pub previous_password: Vec<u8>,
        pub new_user_password: Vec<u8>,
        pub password_salt: Vec<u8>,
        pub password_pepper: Vec<u8>
    }

    pub struct SearchUserByUsernameRequest {
        pub session_id: String,
        pub user_id: String,

        pub search_username: String
    }
}
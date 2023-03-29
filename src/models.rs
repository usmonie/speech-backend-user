pub mod results {
    use uuid::Uuid;

    pub struct User {
        pub id: Uuid,

        pub name: String,
        pub about: Option<String>,

        pub username: String,
        pub avatar: Option<GraphicMediaCore>,

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
    }
}
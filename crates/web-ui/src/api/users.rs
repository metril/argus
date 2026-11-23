//! User administration calls (`/api/v1/users`, admin only)

use super::auth::MessageResponse;
use super::client::{ApiClient, ApiError};

pub use api_types::{CreateUserRequest, Page, UpdateUserRequest, UserInfo, UserRole};

impl ApiClient {
    pub async fn list_users(&self) -> Result<Page<UserInfo>, ApiError> {
        self.get("/users?limit=200").await
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: UserRole,
    ) -> Result<UserInfo, ApiError> {
        let req = CreateUserRequest {
            username: username.to_string(),
            password: password.to_string(),
            role,
        };
        self.post("/users", &req).await
    }

    pub async fn update_user(
        &self,
        id: &str,
        role: Option<UserRole>,
        enabled: Option<bool>,
        default_profile: Option<String>,
    ) -> Result<UserInfo, ApiError> {
        self.patch(
            &format!("/users/{id}"),
            &UpdateUserRequest {
                role,
                enabled,
                default_profile,
            },
        )
        .await
    }

    pub async fn delete_user(&self, id: &str) -> Result<MessageResponse, ApiError> {
        self.delete(&format!("/users/{id}")).await
    }
}

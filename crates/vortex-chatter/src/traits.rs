//! Chattable trait for models that support chatter functionality

use uuid::Uuid;
use vortex_common::Context;

/// Trait for models that support chatter functionality.
///
/// This trait provides a non-intrusive way to add chatter to any model
/// without requiring modification to the model itself.
///
/// # Example
///
/// ```rust,ignore
/// use vortex_chatter::{Chattable, impl_chattable};
///
/// struct Asset {
///     id: Uuid,
///     name: String,
///     status: String,
/// }
///
/// impl_chattable!(Asset, "Asset", tracked_fields: ["name", "status"]);
/// ```
pub trait Chattable: Send + Sync {
    /// Get the model name for polymorphic references.
    ///
    /// This should match the `res_model` value stored in chatter tables.
    fn chatter_model_name() -> &'static str;

    /// Get the record ID for this instance.
    fn chatter_record_id(&self) -> Uuid;

    /// Get display name for notifications.
    ///
    /// Override this to provide a more meaningful name in notifications.
    fn chatter_display_name(&self) -> String {
        format!("{} #{}", Self::chatter_model_name(), self.chatter_record_id())
    }

    /// Get users who should auto-follow on record creation.
    ///
    /// By default, returns an empty list. Override to auto-subscribe
    /// users like the creator or assigned user.
    fn chatter_auto_followers(&self, _ctx: &Context) -> Vec<Uuid> {
        Vec::new()
    }

    /// Fields to track for automatic change messages.
    ///
    /// When these fields change, the chatter system can automatically
    /// post a "field changed" message.
    fn chatter_tracked_fields() -> Vec<&'static str> {
        Vec::new()
    }
}

/// Macro to easily implement the Chattable trait for a model.
///
/// # Basic usage
///
/// ```rust,ignore
/// impl_chattable!(Asset, "Asset");
/// ```
///
/// # With tracked fields
///
/// ```rust,ignore
/// impl_chattable!(Asset, "Asset", tracked_fields: ["name", "status", "location"]);
/// ```
#[macro_export]
macro_rules! impl_chattable {
    ($model:ty, $model_name:expr) => {
        impl $crate::Chattable for $model {
            fn chatter_model_name() -> &'static str {
                $model_name
            }

            fn chatter_record_id(&self) -> uuid::Uuid {
                self.id
            }
        }
    };
    ($model:ty, $model_name:expr, tracked_fields: [$($field:expr),*]) => {
        impl $crate::Chattable for $model {
            fn chatter_model_name() -> &'static str {
                $model_name
            }

            fn chatter_record_id(&self) -> uuid::Uuid {
                self.id
            }

            fn chatter_tracked_fields() -> Vec<&'static str> {
                vec![$($field),*]
            }
        }
    };
}

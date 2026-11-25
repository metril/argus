// Modified by Argus: `ConnectionDescriptor::session_id` (per-device TLS session cache, patch 3) and `ConnectionId::in_request_group` (pool eviction, patch 4) and `ConnectionDescriptor::fresh` (patch 6) and `resend_descriptor`.
use std::{
    hash::{BuildHasher, Hash, Hasher},
    num::NonZeroU64,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use http::{Uri, Version};
use lru::DefaultHasher;

use crate::{conn::net::SocketBindOptions, group::Group, proxy::Matcher, tls::TlsOptions};

/// A key that uniquely identifies a group of interchangeable connections for pooling.
///
/// This ID is derived from all parameters that define a connection endpoint,
/// such as URI, proxy, and local socket bindings. Connections with the same
/// ID are considered equivalent and can be reused.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionId(Arc<(Group, AtomicU64)>);

impl ConnectionId {
    /// Whether the connection was opened for requests of `target`'s request group.
    pub(crate) fn in_request_group(&self, target: &Group) -> bool {
        self.0.0.in_request_group(target)
    }
}

/// A blueprint for creating a new client connection, containing all necessary parameters.
///
/// This descriptor bundles the target `Uri`, HTTP version, `TlsOptions`, proxy settings,
/// and other configurations needed to establish a connection.
#[must_use]
#[derive(Clone)]
pub(crate) struct ConnectionDescriptor {
    uri: Uri,
    version: Option<Version>,
    proxy: Option<Matcher>,
    tls_options: Option<TlsOptions>,
    socket_bind: Option<SocketBindOptions>,
    connection_id: ConnectionId,
    session_id: ConnectionId,
}

// ===== impl ConnectionId =====

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let hash = self.0.1.load(Ordering::Relaxed);
        if hash != 0 {
            state.write_u64(hash);
            return;
        }

        static HASHER: LazyLock<DefaultHasher> = LazyLock::new(DefaultHasher::default);
        let computed_hash = NonZeroU64::new(HASHER.hash_one(&self.0.0))
            .map(NonZeroU64::get)
            .unwrap_or(1);

        let _ = self.0.1.compare_exchange(
            u64::MIN,
            computed_hash,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        state.write_u64(computed_hash);
    }
}

impl PartialEq for ConnectionId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.0.eq(&other.0.0)
    }
}

impl Eq for ConnectionId {}

// ===== impl ConnectionDescriptor =====

impl ConnectionDescriptor {
    /// Create a new [`ConnectionDescriptor`].
    pub(crate) fn new(
        uri: Uri,
        mut group: Group,
        proxy: Option<Matcher>,
        version: Option<Version>,
        tls_options: Option<TlsOptions>,
        socket_bind: Option<SocketBindOptions>,
    ) -> ConnectionDescriptor {
        let (connection_id, session_id) = {
            group
                .uri(uri.clone())
                .version(version)
                .proxy(proxy.clone())
                .socket_bind(socket_bind.clone());
            let session = group.session_scope();
            (
                ConnectionId(Arc::new((group, AtomicU64::new(u64::MIN)))),
                ConnectionId(Arc::new((session, AtomicU64::new(u64::MIN)))),
            )
        };

        ConnectionDescriptor {
            uri,
            proxy,
            version,
            tls_options,
            socket_bind,
            connection_id,
            session_id,
        }
    }

    /// The same descriptor under a unique pool key: its connection is a new one, never an idle
    /// pooled connection. TLS session resumption is unaffected.
    pub(crate) fn fresh(&self) -> ConnectionDescriptor {
        let mut group = self.connection_id.0.0.clone();
        group.fresh();
        ConnectionDescriptor {
            connection_id: ConnectionId(Arc::new((group, AtomicU64::new(u64::MIN)))),
            ..self.clone()
        }
    }

    /// The TLS session cache key: the pool key, except that connections of one session scope
    /// share it (see [`Group::session`]).
    #[inline]
    pub(crate) fn session_id(&self) -> ConnectionId {
        self.session_id.clone()
    }

    /// Returns a [`ConnectionId`] group ID for this descriptor.
    #[inline]
    pub(crate) fn id(&self) -> ConnectionId {
        self.connection_id.clone()
    }

    /// Returns a reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns a mutable reference to the [`Uri`].
    #[inline]
    pub(crate) fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }

    /// Return the negotiated HTTP version, if any.
    pub(crate) fn version(&self) -> Option<Version> {
        self.version
    }

    /// Return a reference to the [`TlsOptions`].
    #[inline]
    pub(crate) fn tls_options(&self) -> Option<&TlsOptions> {
        self.tls_options.as_ref()
    }

    /// Return a reference to the [`Matcher`].
    #[inline]
    pub(crate) fn proxy(&self) -> Option<&Matcher> {
        self.proxy.as_ref()
    }

    /// Return a reference to the [`SocketBindOptions`].
    #[inline]
    pub(crate) fn socket_bind_options(&self) -> Option<&SocketBindOptions> {
        self.socket_bind.as_ref()
    }
}

/// The descriptor the one internal re-send of a canceled (unstarted) request uses: same target
/// and TLS session scope, but a pool key no idle connection can be under, so the re-send dials a
/// new connection instead of taking another (equally dead) idle one.
pub(crate) fn resend_descriptor(original: &ConnectionDescriptor) -> ConnectionDescriptor {
    original.fresh()
}

#[cfg(test)]
pub(crate) mod tests {
    use http::Uri;

    use super::*;

    pub(crate) fn descriptor() -> ConnectionDescriptor {
        ConnectionDescriptor::new(
            Uri::from_static("https://example.test/"),
            Group::default(),
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn the_resend_descriptor_is_a_new_connection_in_the_same_tls_session_scope() {
        let original = descriptor();
        let resend = resend_descriptor(&original);
        assert_ne!(resend.id(), original.id(), "must not share the pool key");
        assert_eq!(resend.session_id(), original.session_id(), "TLS resumption kept");
        assert_eq!(resend.uri(), original.uri());
        // Each re-send is unique, too.
        assert_ne!(resend_descriptor(&original).id(), resend.id());
    }
}

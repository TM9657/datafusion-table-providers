use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use crate::{
    util::{self, ns_lookup::verify_ns_lookup_and_tcp_connect},
    UnsupportedTypeAction,
};
use async_trait::async_trait;
use bb8::ErrorSink;
use bb8_postgres::{
    tokio_postgres::{config::Host, types::ToSql, Config},
    PostgresConnectionManager,
};
#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
use native_tls::{Certificate, TlsConnector};
#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
use postgres_native_tls::MakeTlsConnector;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use snafu::{prelude::*, ResultExt};
use tokio_postgres;

use super::{runtime::run_async_with_tokio, DbConnectionPool};
use crate::sql::db_connection_pool::{
    dbconnection::{postgresconn::PostgresConnection, AsyncDbConnection, DbConnection},
    JoinPushDown,
};

/// The TLS connector type used for PostgreSQL connections.
/// When `postgres-rustls` is enabled, rustls is used (takes precedence if both are enabled).
/// Otherwise, `native-tls` is used (the default with the `postgres` feature).
#[cfg(feature = "postgres-rustls")]
pub type PostgresTlsMaker = tokio_postgres_rustls::MakeRustlsConnect;

#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
pub type PostgresTlsMaker = postgres_native_tls::MakeTlsConnector;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("PostgreSQL connection failed.\n{source}\nFor details, refer to the PostgreSQL documentation: https://www.postgresql.org/docs/17/index.html"))]
    ConnectionPoolError {
        source: bb8_postgres::tokio_postgres::Error,
    },

    #[snafu(display("PostgreSQL connection failed.\n{source}\nAdjust the connection pool parameters for sufficient capacity."))]
    ConnectionPoolRunError {
        source: bb8::RunError<bb8_postgres::tokio_postgres::Error>,
    },

    #[snafu(display(
        "Invalid parameter: {parameter_name}. Ensure the parameter name is correct."
    ))]
    InvalidParameterError { parameter_name: String },

    #[snafu(display("Could not parse {parameter_name} into a valid integer. Ensure it is configured with a valid value."))]
    InvalidIntegerParameterError {
        parameter_name: String,
        source: std::num::ParseIntError,
    },

    #[snafu(display("Cannot connect to PostgreSQL on {host}:{port}. Ensure the host and port are correct and reachable."))]
    InvalidHostOrPortError {
        source: crate::util::ns_lookup::Error,
        host: String,
        port: u16,
    },

    #[snafu(display(
        "Invalid root certificate path: {path}. Ensure it points to a valid root certificate."
    ))]
    InvalidRootCertPathError { path: String },

    #[snafu(display(
        "Failed to read certificate.\n{source}\nEnsure the root certificate path points to a valid certificate."
    ))]
    FailedToReadCertError { source: std::io::Error },

    #[snafu(display(
        "Certificate loading failed.\nEnsure the root certificate path points to a valid certificate."
    ))]
    FailedToLoadCertError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display(
        "TLS connector initialization failed.\nVerify SSL mode and root certificate validity"
    ))]
    FailedToBuildTlsConnectorError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("PostgreSQL connection failed.\n{source}\nFor details, refer to the PostgreSQL documentation: https://www.postgresql.org/docs/17/index.html"))]
    PostgresConnectionError { source: tokio_postgres::Error },

    #[snafu(display("Authentication failed. Verify username and password."))]
    InvalidUsernameOrPassword { source: tokio_postgres::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct PostgresConnectionPool {
    pool: Arc<bb8::Pool<PostgresConnectionManager<PostgresTlsMaker>>>,
    join_push_down: JoinPushDown,
    unsupported_type_action: UnsupportedTypeAction,
}

impl PostgresConnectionPool {
    /// Creates a new instance of `PostgresConnectionPool`.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem creating the connection pool.
    pub async fn new(params: HashMap<String, SecretString>) -> Result<Self> {
        // Remove the "pg_" prefix from the keys to keep backward compatibility
        let params = util::remove_prefix_from_hashmap_keys(params, "pg_");

        let mut connection_string = String::new();
        let mut ssl_mode = "verify-full".to_string();
        let mut ssl_rootcert_path: Option<PathBuf> = None;

        if let Some(pg_connection_string) = params
            .get("connection_string")
            .map(SecretBox::expose_secret)
        {
            let (str, mode, cert_path) = parse_connection_string(pg_connection_string);
            connection_string = str;
            ssl_mode = mode;
            if let Some(cert_path) = cert_path {
                let sslrootcert = cert_path.as_str();
                ensure!(
                    std::path::Path::new(sslrootcert).exists(),
                    InvalidRootCertPathSnafu { path: cert_path }
                );
                ssl_rootcert_path = Some(PathBuf::from(sslrootcert));
            }
        } else {
            if let Some(pg_host) = params.get("host").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("host={pg_host} ").as_str());
            }
            if let Some(pg_user) = params.get("user").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("user={pg_user} ").as_str());
            }
            if let Some(pg_db) = params.get("db").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("dbname={pg_db} ").as_str());
            }
            if let Some(pg_pass) = params.get("pass").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("password={pg_pass} ").as_str());
            }
            if let Some(pg_port) = params.get("port").map(SecretBox::expose_secret) {
                connection_string.push_str(format!("port={pg_port} ").as_str());
            }
        }

        if let Some(pg_sslmode) = params.get("sslmode").map(SecretBox::expose_secret) {
            match pg_sslmode.to_lowercase().as_str() {
                "disable" | "require" | "prefer" | "verify-ca" | "verify-full" => {
                    ssl_mode = pg_sslmode.to_string();
                }
                _ => {
                    InvalidParameterSnafu {
                        parameter_name: "sslmode".to_string(),
                    }
                    .fail()?;
                }
            }
        }
        if let Some(pg_sslrootcert) = params.get("sslrootcert").map(SecretBox::expose_secret) {
            ensure!(
                std::path::Path::new(pg_sslrootcert).exists(),
                InvalidRootCertPathSnafu {
                    path: pg_sslrootcert,
                }
            );

            ssl_rootcert_path = Some(PathBuf::from(pg_sslrootcert));
        }

        let mode = match ssl_mode.as_str() {
            "disable" => "disable",
            "prefer" => "prefer",
            // tokio_postgres supports only disable, require and prefer
            _ => "require",
        };

        connection_string.push_str(format!("sslmode={mode} ").as_str());
        let mut config =
            Config::from_str(connection_string.as_str()).context(ConnectionPoolSnafu)?;

        if let Some(application_name) = params.get("application_name").map(SecretBox::expose_secret)
        {
            config.application_name(application_name);
        }

        verify_postgres_config(&config).await?;

        let connector = build_tls_connector(ssl_mode.as_str(), ssl_rootcert_path).await?;
        test_postgres_connection(connection_string.as_str(), connector.clone()).await?;

        let join_push_down = get_join_context(&config);

        let manager = PostgresConnectionManager::new(config, connector);
        let error_sink = PostgresErrorSink::new();

        let mut connection_pool_size = 10; // The BB8 default is 10
        if let Some(pg_pool_size) = params
            .get("connection_pool_size")
            .map(SecretBox::expose_secret)
        {
            connection_pool_size = pg_pool_size.parse().context(InvalidIntegerParameterSnafu {
                parameter_name: "pool_size".to_string(),
            })?;
        }

        let pool = bb8::Pool::builder()
            .max_size(connection_pool_size)
            .error_sink(Box::new(error_sink))
            .build(manager)
            .await
            .context(ConnectionPoolSnafu)?;

        // Test the connection
        let conn = pool.get().await.context(ConnectionPoolRunSnafu)?;
        conn.execute("SELECT 1", &[])
            .await
            .context(ConnectionPoolSnafu)?;

        Ok(PostgresConnectionPool {
            pool: Arc::new(pool.clone()),
            join_push_down,
            unsupported_type_action: UnsupportedTypeAction::default(),
        })
    }

    /// Specify the action to take when an invalid type is encountered.
    #[must_use]
    pub fn with_unsupported_type_action(mut self, action: UnsupportedTypeAction) -> Self {
        self.unsupported_type_action = action;
        self
    }

    /// Returns a direct connection to the underlying database.
    ///
    /// # Errors
    ///
    /// Returns an error if there is a problem creating the connection pool.
    pub async fn connect_direct(&self) -> super::Result<PostgresConnection> {
        let pool = Arc::clone(&self.pool);
        let conn = pool.get_owned().await.context(ConnectionPoolRunSnafu)?;
        Ok(PostgresConnection::new(conn))
    }
}

fn parse_connection_string(pg_connection_string: &str) -> (String, String, Option<String>) {
    let mut connection_string = String::new();
    let mut ssl_mode = "verify-full".to_string();
    let mut ssl_rootcert_path: Option<String> = None;

    let str = pg_connection_string;
    let str_params: Vec<&str> = str.split_whitespace().collect();
    for param in str_params {
        let param = param.split('=').collect::<Vec<&str>>();
        if let (Some(&name), Some(&value)) = (param.first(), param.get(1)) {
            match name {
                "sslmode" => {
                    ssl_mode = value.to_string();
                }
                "sslrootcert" => {
                    ssl_rootcert_path = Some(value.to_string());
                }
                _ => {
                    connection_string.push_str(format!("{name}={value} ").as_str());
                }
            }
        }
    }

    (connection_string, ssl_mode, ssl_rootcert_path)
}

fn get_join_context(config: &Config) -> JoinPushDown {
    let mut join_push_context_str = String::new();
    for host in config.get_hosts() {
        join_push_context_str.push_str(&format!("host={host:?},"));
    }
    if !config.get_ports().is_empty() {
        join_push_context_str.push_str(&format!("port={port},", port = config.get_ports()[0]));
    }
    if let Some(dbname) = config.get_dbname() {
        join_push_context_str.push_str(&format!("db={dbname},"));
    }
    if let Some(user) = config.get_user() {
        join_push_context_str.push_str(&format!("user={user},"));
    }

    JoinPushDown::AllowedFor(join_push_context_str)
}

async fn test_postgres_connection(
    connection_string: &str,
    connector: PostgresTlsMaker,
) -> Result<()> {
    match tokio_postgres::connect(connection_string, connector).await {
        Ok(_) => Ok(()),
        Err(err) => {
            if let Some(code) = err.code() {
                if *code == tokio_postgres::error::SqlState::INVALID_PASSWORD {
                    return Err(Error::InvalidUsernameOrPassword { source: err });
                }
            }

            Err(Error::PostgresConnectionError { source: err })
        }
    }
}

async fn verify_postgres_config(config: &Config) -> Result<()> {
    for host in config.get_hosts() {
        for port in config.get_ports() {
            if let Host::Tcp(host) = host {
                verify_ns_lookup_and_tcp_connect(host, *port)
                    .await
                    .context(InvalidHostOrPortSnafu { host, port: *port })?;
            }
        }
    }

    Ok(())
}

/// Build the TLS connector from SSL mode and optional root certificate path.
/// The implementation is chosen at compile time based on the TLS feature flag.
#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
async fn build_tls_connector(
    ssl_mode: &str,
    ssl_rootcert_path: Option<PathBuf>,
) -> Result<PostgresTlsMaker> {
    let mut certs: Option<Vec<Certificate>> = None;
    if let Some(path) = ssl_rootcert_path {
        let buf = tokio::fs::read(path).await.context(FailedToReadCertSnafu)?;
        certs = Some(parse_native_tls_certs(&buf)?);
    }
    let tls_connector = get_native_tls_connector(ssl_mode, certs)?;
    Ok(MakeTlsConnector::new(tls_connector))
}

#[cfg(feature = "postgres-rustls")]
async fn build_tls_connector(
    ssl_mode: &str,
    ssl_rootcert_path: Option<PathBuf>,
) -> Result<PostgresTlsMaker> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_postgres_rustls::MakeRustlsConnect;

    let mut root_store = RootCertStore::empty();

    // If ssl_mode is "disable", we still need a config but it won't be used
    if ssl_mode != "disable" {
        if let Some(path) = ssl_rootcert_path {
            let buf = tokio::fs::read(&path)
                .await
                .context(FailedToReadCertSnafu)?;
            let certs = parse_rustls_certs(&buf)?;
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| Error::FailedToLoadCertError {
                        source: Box::new(e),
                    })?;
            }
        } else {
            // Use webpki roots as default trusted certificates
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    let config_builder = ClientConfig::builder().with_root_certificates(root_store);
    let mut tls_config = config_builder.with_no_client_auth();

    // Match native-tls behavior for ssl_mode settings
    if ssl_mode != "verify-full" && ssl_mode != "verify-ca" {
        // Equivalent to danger_accept_invalid_certs
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new()));
    }

    Ok(MakeRustlsConnect::new(tls_config))
}

#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
fn get_native_tls_connector(
    ssl_mode: &str,
    rootcerts: Option<Vec<Certificate>>,
) -> Result<TlsConnector> {
    let mut builder = TlsConnector::builder();

    if ssl_mode == "disable" {
        return builder
            .build()
            .map_err(|e| Error::FailedToBuildTlsConnectorError {
                source: Box::new(e),
            });
    }

    if let Some(certs) = rootcerts {
        for cert in certs {
            builder.add_root_certificate(cert);
        }
    }

    builder
        .danger_accept_invalid_hostnames(ssl_mode != "verify-full")
        .danger_accept_invalid_certs(ssl_mode != "verify-full" && ssl_mode != "verify-ca")
        .build()
        .map_err(|e| Error::FailedToBuildTlsConnectorError {
            source: Box::new(e),
        })
}

#[cfg(all(feature = "postgres-native-tls", not(feature = "postgres-rustls")))]
fn parse_native_tls_certs(buf: &[u8]) -> Result<Vec<Certificate>> {
    Certificate::from_der(buf)
        .map(|x| vec![x])
        .or_else(|_| {
            pem::parse_many(buf)
                .unwrap_or_default()
                .iter()
                .map(pem::encode)
                .map(|s| Certificate::from_pem(s.as_bytes()))
                .collect()
        })
        .map_err(|e| Error::FailedToLoadCertError {
            source: Box::new(e),
        })
}

#[cfg(feature = "postgres-rustls")]
fn parse_rustls_certs(buf: &[u8]) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use std::io::BufReader;

    // Try DER first
    if !buf.is_empty() {
        // Check if it looks like PEM
        if buf.starts_with(b"-----") {
            let mut reader = BufReader::new(buf);
            let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::FailedToLoadCertError {
                    source: Box::new(e),
                })?;
            if !certs.is_empty() {
                return Ok(certs);
            }
        }
        // Treat as DER
        return Ok(vec![rustls_pki_types::CertificateDer::from(buf.to_vec())]);
    }

    Err(Error::FailedToLoadCertError {
        source: "Empty certificate data".into(),
    })
}

/// Dangerous TLS verifier module for rustls (used when ssl_mode is not verify-full/verify-ca)
#[cfg(feature = "postgres-rustls")]
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl NoCertificateVerification {
        pub fn new() -> Self {
            Self
        }
    }

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PostgresErrorSink {}

impl PostgresErrorSink {
    pub fn new() -> Self {
        PostgresErrorSink {}
    }
}

impl<E> ErrorSink<E> for PostgresErrorSink
where
    E: std::fmt::Debug,
    E: std::fmt::Display,
{
    fn sink(&self, error: E) {
        tracing::debug!("Postgres Pool Error: {}", error);
    }

    fn boxed_clone(&self) -> Box<dyn ErrorSink<E>> {
        Box::new(*self)
    }
}

#[async_trait]
impl
    DbConnectionPool<
        bb8::PooledConnection<'static, PostgresConnectionManager<PostgresTlsMaker>>,
        &'static (dyn ToSql + Sync),
    > for PostgresConnectionPool
{
    async fn connect(
        &self,
    ) -> super::Result<
        Box<
            dyn DbConnection<
                bb8::PooledConnection<'static, PostgresConnectionManager<PostgresTlsMaker>>,
                &'static (dyn ToSql + Sync),
            >,
        >,
    > {
        let pool = Arc::clone(&self.pool);
        let get_conn = async || pool.get_owned().await.context(ConnectionPoolRunSnafu);
        let conn = run_async_with_tokio(get_conn).await?;
        Ok(Box::new(
            PostgresConnection::new(conn)
                .with_unsupported_type_action(self.unsupported_type_action),
        ))
    }

    fn join_push_down(&self) -> JoinPushDown {
        self.join_push_down.clone()
    }
}

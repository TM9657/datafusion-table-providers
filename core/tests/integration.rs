use rand::Rng;

mod arrow_record_batch_gen;
#[cfg(feature = "clickhouse")]
mod clickhouse;
#[cfg(any(
    feature = "clickhouse",
    feature = "mongodb",
    feature = "mysql",
    feature = "mysql-rustls",
    feature = "postgres",
    feature = "postgres-rustls"
))]
mod docker;
#[cfg(all(feature = "duckdb", feature = "federation"))]
mod duckdb;
#[cfg(feature = "flight")]
mod flight;
#[cfg(feature = "mongodb")]
mod mongodb;
#[cfg(any(feature = "mysql", feature = "mysql-rustls"))]
mod mysql;
#[cfg(any(feature = "postgres", feature = "postgres-rustls"))]
mod postgres;
#[cfg(feature = "sqlite")]
mod sqlite;

fn container_registry() -> String {
    std::env::var("CONTAINER_REGISTRY")
        .unwrap_or_else(|_| "public.ecr.aws/docker/library/".to_string())
}

fn get_random_port() -> usize {
    rand::rng().random_range(15432..65535)
}

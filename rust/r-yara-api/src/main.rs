/// R-YARA API Server
/// Provides REST API for R-YARA dictionary and rule operations

mod feed;

use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use r_yara_store::{CryptexEntry, CryptexStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use r_yara_feed_scanner::FeedScanner;

#[derive(Deserialize)]
struct LookupParams {
    symbol: Option<String>,
    pyro_name: Option<String>,
}

#[derive(Deserialize)]
struct SearchParams {
    query: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

type SharedStore = Arc<RwLock<CryptexStore>>;

/// Combined application state
#[derive(Clone)]
struct AppState {
    store: SharedStore,
    scanner: Arc<RwLock<FeedScanner>>,
}

/// Lookup Cryptex entry
async fn lookup_entry(
    Query(params): Query<LookupParams>,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ApiResponse<CryptexEntry>>, StatusCode> {
    let store = state.store.read().await;
    
    let entry = if let Some(symbol) = params.symbol {
        store.lookup_by_symbol(&symbol).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else if let Some(codename) = params.pyro_name {
        store.lookup_by_codename(&codename).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Either 'symbol' or 'pyro_name' parameter required".to_string()),
        }));
    };

    Ok(Json(ApiResponse {
        success: entry.is_some(),
        data: entry,
        error: None,
    }))
}

/// Get all entries
async fn get_all_entries(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ApiResponse<Vec<CryptexEntry>>>, StatusCode> {
    let store = state.store.read().await;
    let entries = store.get_all_entries().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: Some(entries),
        error: None,
    }))
}

/// Search entries
async fn search_entries(
    Query(params): Query<SearchParams>,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ApiResponse<Vec<CryptexEntry>>>, StatusCode> {
    let store = state.store.read().await;
    let results = store.search_entries(&params.query).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: Some(results),
        error: None,
    }))
}

/// Get statistics
async fn get_stats(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<Json<ApiResponse<r_yara_store::CryptexStatistics>>, StatusCode> {
    let store = state.store.read().await;
    let stats = store.get_statistics().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
    }))
}

#[tokio::main]
async fn main() {
    // Initialize store
    let db_path = std::env::var("CRYPTEX_DB_PATH").unwrap_or_else(|_| "cryptex.db".to_string());
    let store = CryptexStore::open(&db_path)
        .expect("Failed to open Cryptex store");
    
    let shared_store = Arc::new(RwLock::new(store));

    // Initialize feed scanner
    let feed_scanner = Arc::new(RwLock::new(FeedScanner::new()));

    // Create combined state
    let app_state = AppState {
        store: shared_store.clone(),
        scanner: feed_scanner.clone(),
    };

    // Build router with R-YARA endpoints
    let app = Router::new()
        .route("/api/v2/r-yara/dictionary/lookup", get(lookup_entry))
        .route("/api/v2/r-yara/dictionary/entries", get(get_all_entries))
        .route("/api/v2/r-yara/dictionary/search", get(search_entries))
        .route("/api/v2/r-yara/dictionary/stats", get(get_stats))
        .merge(feed::create_router(feed_scanner))
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3006").await.unwrap();
    println!("R-YARA API server listening on http://0.0.0.0:3006");
    
    axum::serve(listener, app).await.unwrap();
}


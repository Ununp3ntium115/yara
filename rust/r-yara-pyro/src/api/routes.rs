//! API route definitions

#![allow(dead_code)]

use axum::{
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use super::handlers;

/// Route definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub path: String,
    pub method: String,
    pub handler: String,
    pub description: String,
}

/// All R-YARA API routes (Fire Hydrant API)
pub fn get_routes() -> Vec<Route> {
    vec![
        // Health
        Route {
            path: "/health".to_string(),
            method: "GET".to_string(),
            handler: "health".to_string(),
            description: "Health check endpoint".to_string(),
        },
        // Dictionary
        Route {
            path: "/dictionary/lookup".to_string(),
            method: "GET".to_string(),
            handler: "dictionary_lookup".to_string(),
            description: "Look up a symbol or codename".to_string(),
        },
        Route {
            path: "/dictionary/search".to_string(),
            method: "GET".to_string(),
            handler: "dictionary_search".to_string(),
            description: "Search dictionary entries".to_string(),
        },
        Route {
            path: "/dictionary/stats".to_string(),
            method: "GET".to_string(),
            handler: "dictionary_stats".to_string(),
            description: "Get dictionary statistics".to_string(),
        },
        // Scanning
        Route {
            path: "/scan/file".to_string(),
            method: "POST".to_string(),
            handler: "scan_file".to_string(),
            description: "Scan a file with YARA rules".to_string(),
        },
        Route {
            path: "/scan/data".to_string(),
            method: "POST".to_string(),
            handler: "scan_data".to_string(),
            description: "Scan raw data with YARA rules".to_string(),
        },
        Route {
            path: "/scan/batch".to_string(),
            method: "POST".to_string(),
            handler: "batch_scan".to_string(),
            description: "Scan multiple files with YARA rules".to_string(),
        },
        Route {
            path: "/scan/directory".to_string(),
            method: "POST".to_string(),
            handler: "scan_directory".to_string(),
            description: "Scan all files in a directory".to_string(),
        },
        // Modules
        Route {
            path: "/modules".to_string(),
            method: "GET".to_string(),
            handler: "list_modules".to_string(),
            description: "List available YARA modules".to_string(),
        },
        // Rules
        Route {
            path: "/rules".to_string(),
            method: "GET".to_string(),
            handler: "list_rules".to_string(),
            description: "List loaded YARA rules".to_string(),
        },
        Route {
            path: "/rules/load".to_string(),
            method: "POST".to_string(),
            handler: "load_rules".to_string(),
            description: "Load YARA rules from string or file".to_string(),
        },
        Route {
            path: "/rules/validate".to_string(),
            method: "POST".to_string(),
            handler: "validate_rule".to_string(),
            description: "Validate YARA rule syntax".to_string(),
        },
        Route {
            path: "/rules/compile".to_string(),
            method: "POST".to_string(),
            handler: "compile_rules".to_string(),
            description: "Compile YARA rules to binary format".to_string(),
        },
        // Transcoding
        Route {
            path: "/transcode/encode".to_string(),
            method: "POST".to_string(),
            handler: "transcode_encode".to_string(),
            description: "Encode rule with codenames".to_string(),
        },
        Route {
            path: "/transcode/decode".to_string(),
            method: "POST".to_string(),
            handler: "transcode_decode".to_string(),
            description: "Decode rule from codenames".to_string(),
        },
        // Feed scanning
        Route {
            path: "/feed/scan/{use_case}".to_string(),
            method: "POST".to_string(),
            handler: "scan_feeds".to_string(),
            description: "Scan feeds for YARA rules".to_string(),
        },
        // Worker
        Route {
            path: "/worker/task".to_string(),
            method: "POST".to_string(),
            handler: "submit_task".to_string(),
            description: "Submit a task to worker queue".to_string(),
        },
        Route {
            path: "/worker/task/{task_id}".to_string(),
            method: "GET".to_string(),
            handler: "get_task_status".to_string(),
            description: "Get task status".to_string(),
        },
        // Stats
        Route {
            path: "/stats".to_string(),
            method: "GET".to_string(),
            handler: "get_stats".to_string(),
            description: "Get system statistics".to_string(),
        },
        // Streaming
        Route {
            path: "/scan/streaming".to_string(),
            method: "POST".to_string(),
            handler: "streaming_scan".to_string(),
            description: "Streaming directory scan with events".to_string(),
        },
        // Remote rule loading
        Route {
            path: "/rules/load/zip".to_string(),
            method: "POST".to_string(),
            handler: "load_rules_from_zip".to_string(),
            description: "Load rules from ZIP archive".to_string(),
        },
        Route {
            path: "/rules/load/directory".to_string(),
            method: "POST".to_string(),
            handler: "load_rules_from_directory".to_string(),
            description: "Load rules from directory".to_string(),
        },
        // Database
        Route {
            path: "/db/scan".to_string(),
            method: "POST".to_string(),
            handler: "store_scan_result".to_string(),
            description: "Store scan result in database".to_string(),
        },
        Route {
            path: "/db/query/hash".to_string(),
            method: "GET".to_string(),
            handler: "query_scans_by_hash".to_string(),
            description: "Query scans by file hash".to_string(),
        },
        Route {
            path: "/db/query/rule".to_string(),
            method: "GET".to_string(),
            handler: "query_scans_by_rule".to_string(),
            description: "Query scans by rule name".to_string(),
        },
        Route {
            path: "/db/stats".to_string(),
            method: "GET".to_string(),
            handler: "get_database_stats".to_string(),
            description: "Get database statistics".to_string(),
        },
        Route {
            path: "/db/recent".to_string(),
            method: "GET".to_string(),
            handler: "get_recent_scans".to_string(),
            description: "Get recent scans".to_string(),
        },
    ]
}

/// Create the API router (Fire Hydrant API)
pub fn create_router() -> Router {
    Router::new()
        // Health
        .route("/health", get(handlers::health))
        // Dictionary
        .route("/dictionary/lookup", get(handlers::dictionary_lookup))
        .route("/dictionary/search", get(handlers::dictionary_search))
        .route("/dictionary/stats", get(handlers::dictionary_stats))
        // Scanning
        .route("/scan/file", post(handlers::scan_file))
        .route("/scan/data", post(handlers::scan_data))
        .route("/scan/batch", post(handlers::batch_scan))
        .route("/scan/directory", post(handlers::scan_directory))
        .route("/scan/streaming", post(handlers::streaming_scan))
        // Modules
        .route("/modules", get(handlers::list_modules))
        // Rules
        .route("/rules", get(handlers::list_rules))
        .route("/rules/load", post(handlers::load_rules))
        .route("/rules/load/zip", post(handlers::load_rules_from_zip))
        .route("/rules/load/directory", post(handlers::load_rules_from_directory))
        .route("/rules/validate", post(handlers::validate_rule))
        .route("/rules/compile", post(handlers::compile_rules))
        // Transcoding
        .route("/transcode/encode", post(handlers::transcode_encode))
        .route("/transcode/decode", post(handlers::transcode_decode))
        // Feed scanning
        .route("/feed/scan/:use_case", post(handlers::scan_feeds))
        // Worker
        .route("/worker/task", post(handlers::submit_task))
        .route("/worker/task/:task_id", get(handlers::get_task_status))
        // Database
        .route("/db/scan", post(handlers::store_scan_result))
        .route("/db/query/hash", get(handlers::query_scans_by_hash))
        .route("/db/query/rule", get(handlers::query_scans_by_rule))
        .route("/db/stats", get(handlers::get_database_stats))
        .route("/db/recent", get(handlers::get_recent_scans))
        // Stats
        .route("/stats", get(handlers::get_stats))
}

/// Generate OpenAPI spec
pub fn openapi_spec() -> serde_json::Value {
    let routes = get_routes();
    let mut paths = serde_json::Map::new();

    for route in routes {
        let path_item = serde_json::json!({
            route.method.to_lowercase(): {
                "summary": route.description,
                "operationId": route.handler,
                "tags": ["r-yara"],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": { "type": "object" }
                            }
                        }
                    }
                }
            }
        });

        paths.insert(route.path, path_item);
    }

    serde_json::json!({
        "openapi": "3.0.0",
        "info": {
            "title": "PYRO Fire Hydrant API",
            "version": crate::VERSION,
            "description": "High-pressure YARA scanning powered by R-YARA - unified scanner with batch and directory scanning"
        },
        "paths": paths,
        "tags": [
            { "name": "r-yara", "description": "Fire Hydrant YARA operations" }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routes_defined() {
        let routes = get_routes();
        assert!(!routes.is_empty());
        assert!(routes.iter().any(|r| r.path == "/health"));
    }

    #[test]
    fn test_openapi_spec() {
        let spec = openapi_spec();
        assert_eq!(spec["info"]["title"], "PYRO Fire Hydrant API");
    }
}

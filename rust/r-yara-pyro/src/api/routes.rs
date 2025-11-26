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

/// All R-YARA API routes
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
        // Rules
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
    ]
}

/// Create the API router
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
        // Rules
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
            "title": "R-YARA API",
            "version": crate::VERSION,
            "description": "R-YARA YARA rule management and scanning API"
        },
        "paths": paths,
        "tags": [
            { "name": "r-yara", "description": "R-YARA operations" }
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
        assert_eq!(spec["info"]["title"], "R-YARA API");
    }
}

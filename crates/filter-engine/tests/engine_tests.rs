//! Integration tests for filter engine

use filter_engine::{FilterEngine, FilterList};

#[tokio::test]
async fn test_engine_initialization() {
    let temp_dir = std::env::temp_dir().join("filter-engine-integration-1");
    let engine = FilterEngine::new(temp_dir).unwrap();

    assert!(engine.is_enabled());

    let stats = engine.stats();
    assert_eq!(stats.total_requests, 0);
}

#[tokio::test]
async fn test_filter_list_management() {
    let temp_dir = std::env::temp_dir().join("filter-engine-integration-2");
    let engine = FilterEngine::new(temp_dir).unwrap();

    let list_manager = engine.list_manager();

    // Check default lists are loaded
    let lists = list_manager.get_all_lists();
    assert!(!lists.is_empty());

    // Find EasyList
    let easylist = lists.iter().find(|l| l.id == "easylist");
    assert!(easylist.is_some());
    assert_eq!(easylist.unwrap().name, "EasyList");
}

#[tokio::test]
async fn test_enable_disable() {
    let temp_dir = std::env::temp_dir().join("filter-engine-integration-3");
    let engine = FilterEngine::new(temp_dir).unwrap();

    // Initially enabled
    assert!(engine.is_enabled());

    // Disable
    engine.set_enabled(false);
    assert!(!engine.is_enabled());

    // When disabled, all requests should be allowed
    let result = engine.check_request(
        "https://ads.example.com/banner.jpg",
        "https://example.com",
        "image",
    ).unwrap();
    assert!(!result.blocked);

    // Re-enable
    engine.set_enabled(true);
    assert!(engine.is_enabled());
}

#[tokio::test]
async fn test_stats_tracking() {
    let temp_dir = std::env::temp_dir().join("filter-engine-integration-4");
    let engine = FilterEngine::new(temp_dir).unwrap();

    // Manually trigger some requests (even without filters loaded, stats should track)
    engine.set_enabled(false); // Disable to ensure requests pass through

    let _ = engine.check_request(
        "https://example.com/script.js",
        "https://example.com",
        "script",
    );

    let _ = engine.check_request(
        "https://example.com/image.png",
        "https://example.com",
        "image",
    );

    let stats = engine.stats();
    assert_eq!(stats.total_requests, 2);
    assert_eq!(stats.allowed_requests, 2);

    // Reset stats
    engine.reset_stats();
    let reset_stats = engine.stats();
    assert_eq!(reset_stats.total_requests, 0);
}

#[tokio::test]
async fn test_custom_filter_list() {
    let temp_dir = std::env::temp_dir().join("filter-engine-integration-5");
    let engine = FilterEngine::new(temp_dir).unwrap();

    let list_manager = engine.list_manager();

    // Add a custom filter list
    let custom_list = FilterList::new(
        "custom-test".to_string(),
        "Custom Test List".to_string(),
        "https://example.com/custom.txt".to_string(),
    );

    list_manager.add_list(custom_list);

    // Verify it was added
    let retrieved = list_manager.get_list("custom-test");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Custom Test List");

    // Disable it
    list_manager.set_enabled("custom-test", false).unwrap();
    let disabled = list_manager.get_list("custom-test").unwrap();
    assert!(!disabled.enabled);

    // Remove it
    list_manager.remove_list("custom-test").unwrap();
    assert!(list_manager.get_list("custom-test").is_none());
}

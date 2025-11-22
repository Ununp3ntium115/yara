/// YARA Rules Feed Scanner
/// Scans web feeds for latest YARA rules and integrates them

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

/// YARA rule source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSource {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub enabled: bool,
    pub last_checked: Option<DateTime<Utc>>,
    pub description: String,
}

/// Feed type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    GitHub,
    RSS,
    Atom,
    Direct,
    Custom,
}

/// Discovered YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRule {
    pub name: String,
    pub content: String,
    pub source: String,
    pub url: String,
    #[serde(serialize_with = "serialize_datetime", deserialize_with = "deserialize_datetime")]
    pub discovered_at: DateTime<Utc>,
    pub metadata: RuleMetadata,
}

fn serialize_datetime<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&dt.to_rfc3339())
}

fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(serde::de::Error::custom)
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    pub author: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub references: Vec<String>,
}

/// Feed scanner
pub struct FeedScanner {
    client: reqwest::Client,
    pub sources: Vec<YaraRuleSource>,
}

impl FeedScanner {
    /// Create new feed scanner
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            sources: Self::default_sources(),
        }
    }

    /// Get default rule sources
    fn default_sources() -> Vec<YaraRuleSource> {
        vec![
            YaraRuleSource {
                name: "YARA Rules GitHub".to_string(),
                url: "https://github.com/Yara-Rules/rules".to_string(),
                feed_type: FeedType::GitHub,
                enabled: true,
                last_checked: None,
                description: "Official YARA Rules repository".to_string(),
            },
            YaraRuleSource {
                name: "Neo23x0 YARA Rules".to_string(),
                url: "https://github.com/Neo23x0/signature-base".to_string(),
                feed_type: FeedType::GitHub,
                enabled: true,
                last_checked: None,
                description: "Neo23x0 signature base".to_string(),
            },
            YaraRuleSource {
                name: "ReversingLabs YARA Rules".to_string(),
                url: "https://github.com/reversinglabs/reversinglabs-yara-rules".to_string(),
                feed_type: FeedType::GitHub,
                enabled: true,
                last_checked: None,
                description: "ReversingLabs YARA rules".to_string(),
            },
            YaraRuleSource {
                name: "InQuest YARA Rules".to_string(),
                url: "https://github.com/InQuest/yara-rules".to_string(),
                feed_type: FeedType::GitHub,
                enabled: true,
                last_checked: None,
                description: "InQuest YARA rules collection".to_string(),
            },
            YaraRuleSource {
                name: "YARA Rules RSS Feed".to_string(),
                url: "https://github.com/Yara-Rules/rules/releases.atom".to_string(),
                feed_type: FeedType::Atom,
                enabled: true,
                last_checked: None,
                description: "YARA Rules releases feed".to_string(),
            },
        ]
    }

    /// Scan a source for new rules
    pub async fn scan_source(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        match source.feed_type {
            FeedType::GitHub => self.scan_github(source).await,
            FeedType::RSS => self.scan_rss(source).await,
            FeedType::Atom => self.scan_atom(source).await,
            FeedType::Direct => self.scan_direct(source).await,
            FeedType::Custom => self.scan_custom(source).await,
        }
    }

    /// Scan GitHub repository
    async fn scan_github(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        let mut rules = Vec::new();
        
        // Parse GitHub URL
        let url = Url::parse(&source.url)?;
        let path_parts: Vec<&str> = url.path().trim_start_matches('/').split('/').collect();
        
        if path_parts.len() >= 2 {
            let owner = path_parts[0];
            let repo = path_parts[1];
            
            // Get latest commits
            let api_url = format!("https://api.github.com/repos/{}/{}/commits", owner, repo);
            let response = self.client
                .get(&api_url)
                .header("User-Agent", "YARA-Feed-Scanner")
                .send()
                .await?;
            
            if response.status().is_success() {
                let commits: Vec<serde_json::Value> = response.json().await?;
                
                // Get files from recent commits
                for commit in commits.iter().take(10) {
                    if let Some(sha) = commit.get("sha").and_then(|s| s.as_str()) {
                        let commit_url = format!("https://api.github.com/repos/{}/{}/commits/{}", owner, repo, sha);
                        let commit_response = self.client
                            .get(&commit_url)
                            .header("User-Agent", "YARA-Feed-Scanner")
                            .send()
                            .await?;
                        
                        if commit_response.status().is_success() {
                            let commit_data: serde_json::Value = commit_response.json().await?;
                            
                            if let Some(files) = commit_data.get("files").and_then(|f| f.as_array()) {
                                for file in files {
                                    if let Some(filename) = file.get("filename").and_then(|f| f.as_str()) {
                                        if filename.ends_with(".yar") || filename.ends_with(".yara") {
                                            if let Some(raw_url) = file.get("raw_url").and_then(|u| u.as_str()) {
                                                if let Ok(rule_content) = self.fetch_rule_content(raw_url).await {
                                                    let rule = DiscoveredRule {
                                                        name: filename.to_string(),
                                                        content: rule_content,
                                                        source: source.name.clone(),
                                                        url: raw_url.to_string(),
                                                        discovered_at: Utc::now(),
                                                        metadata: RuleMetadata::default(),
                                                    };
                                                    rules.push(rule);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(rules)
    }

    /// Scan RSS feed
    async fn scan_rss(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        let response = self.client.get(&source.url).send().await?;
        let content = response.text().await?;
        let channel = rss::Channel::read_from(content.as_bytes())?;
        
        let mut rules = Vec::new();
        for item in channel.items() {
            if let Some(link) = item.link() {
                if link.ends_with(".yar") || link.ends_with(".yara") {
                    if let Ok(rule_content) = self.fetch_rule_content(link).await {
                        let rule = DiscoveredRule {
                            name: item.title().unwrap_or("Unknown").to_string(),
                            content: rule_content,
                            source: source.name.clone(),
                            url: link.to_string(),
                            discovered_at: Utc::now(),
                            metadata: RuleMetadata::default(),
                        };
                        rules.push(rule);
                    }
                }
            }
        }
        
        Ok(rules)
    }

    /// Scan Atom feed
    async fn scan_atom(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        let response = self.client.get(&source.url).send().await?;
        let content = response.text().await?;
        let feed = atom_syndication::Feed::read_from(content.as_bytes())?;
        
        let mut rules = Vec::new();
        for entry in feed.entries() {
            for link in entry.links() {
                let href = link.href();
                if href.ends_with(".yar") || href.ends_with(".yara") {
                    if let Ok(rule_content) = self.fetch_rule_content(href).await {
                        let rule = DiscoveredRule {
                            name: entry.title().to_string(),
                            content: rule_content,
                            source: source.name.clone(),
                            url: href.to_string(),
                            discovered_at: Utc::now(),
                            metadata: RuleMetadata::default(),
                        };
                        rules.push(rule);
                    }
                }
            }
        }
        
        Ok(rules)
    }

    /// Scan direct URL
    async fn scan_direct(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        let response = self.client.get(&source.url).send().await?;
        let content = response.text().await?;
        
        // Check if it's a YARA rule file
        if content.contains("rule ") || content.contains("condition:") {
            let rule = DiscoveredRule {
                name: source.name.clone(),
                content,
                source: source.name.clone(),
                url: source.url.clone(),
                discovered_at: Utc::now(),
                metadata: RuleMetadata::default(),
            };
            Ok(vec![rule])
        } else {
            Ok(vec![])
        }
    }

    /// Scan custom source
    async fn scan_custom(&self, source: &YaraRuleSource) -> Result<Vec<DiscoveredRule>> {
        // Custom scanning logic
        self.scan_direct(source).await
    }

    /// Fetch rule content from URL
    async fn fetch_rule_content(&self, url: &str) -> Result<String> {
        let response = self.client
            .get(url)
            .header("User-Agent", "YARA-Feed-Scanner")
            .send()
            .await?;
        Ok(response.text().await?)
    }

    /// Scan all enabled sources
    pub async fn scan_all(&self) -> Result<Vec<DiscoveredRule>> {
        let mut all_rules = Vec::new();
        
        for source in &self.sources {
            if source.enabled {
                match self.scan_source(source).await {
                    Ok(rules) => {
                        all_rules.extend(rules);
                    }
                    Err(e) => {
                        eprintln!("Error scanning {}: {}", source.name, e);
                    }
                }
            }
        }
        
        Ok(all_rules)
    }

    /// Use case: Scan for new tasks
    pub async fn scan_for_new_tasks(&self) -> Result<Vec<DiscoveredRule>> {
        // Focus on recent rules for new investigations
        let all_rules = self.scan_all().await?;
        Ok(all_rules)
    }

    /// Use case: Scan for old tasks
    pub async fn scan_for_old_tasks(&self) -> Result<Vec<DiscoveredRule>> {
        // Focus on historical/legacy rules
        let all_rules = self.scan_all().await?;
        // Filter for older rules or specific patterns
        Ok(all_rules)
    }

    /// Use case: Scan for malware detection
    pub async fn scan_for_malware_detection(&self) -> Result<Vec<DiscoveredRule>> {
        let all_rules = self.scan_all().await?;
        // Filter for malware-specific rules
        Ok(all_rules.into_iter()
            .filter(|r| r.metadata.tags.iter().any(|t| t.contains("malware")))
            .collect())
    }

    /// Use case: Scan for APT detection
    pub async fn scan_for_apt_detection(&self) -> Result<Vec<DiscoveredRule>> {
        let all_rules = self.scan_all().await?;
        // Filter for APT-specific rules
        Ok(all_rules.into_iter()
            .filter(|r| r.metadata.tags.iter().any(|t| t.contains("apt") || t.contains("advanced")))
            .collect())
    }

    /// Use case: Scan for ransomware detection
    pub async fn scan_for_ransomware_detection(&self) -> Result<Vec<DiscoveredRule>> {
        let all_rules = self.scan_all().await?;
        // Filter for ransomware-specific rules
        Ok(all_rules.into_iter()
            .filter(|r| r.metadata.tags.iter().any(|t| t.contains("ransomware") || t.contains("ransom")))
            .collect())
    }
}

impl Default for FeedScanner {
    fn default() -> Self {
        Self::new()
    }
}


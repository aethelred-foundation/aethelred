//! # Sovereign Border Visualizer
//!
//! **"Watch Data Hit Borders Like Waves on Rocks"**
//!
//! This module provides a visual representation of data flows across
//! jurisdictional boundaries. Users can see:
//!
//! 1. Data location in real-time
//! 2. Border crossings (allowed/blocked)
//! 3. TEE enclaves as secure zones
//! 4. Regulatory zones with compliance status
//!
//! ## The 3D Data Flow Map
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                    🌍 SOVEREIGN BORDER VISUALIZER                             ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║                           WORLD DATA FLOW MAP                                 ║
//! ║                                                                               ║
//! ║     ┌─────────────────────────────────────────────────────────────────────┐  ║
//! ║     │                                                                     │  ║
//! ║     │                    🇪🇺 EUROPEAN UNION                               │  ║
//! ║     │                   ┌──────────────────┐                              │  ║
//! ║     │                   │ Frankfurt ⬡      │                              │  ║
//! ║     │                   │   GDPR Zone      │                              │  ║
//! ║     │                   └────────┬─────────┘                              │  ║
//! ║     │                            │ ❌ BLOCKED                             │  ║
//! ║     │                            ▼                                        │  ║
//! ║     │   🇺🇸 USA              ╳╳╳╳╳╳╳╳                                    │  ║
//! ║     │  ┌──────────────┐                                                   │  ║
//! ║     │  │ New York ⬡   │        ✅ ALLOWED                                │  ║
//! ║     │  │  US Zone     │◄──────────────────────────┐                       │  ║
//! ║     │  └──────────────┘                           │                       │  ║
//! ║     │                                             │                       │  ║
//! ║     │   🇦🇪 UAE                    🇸🇬 SINGAPORE  │                       │  ║
//! ║     │  ┌───────────────────┐      ┌──────────────┴──┐                     │  ║
//! ║     │  │ Abu Dhabi ⬡       │      │ Singapore ⬡     │                     │  ║
//! ║     │  │  [TEE ENCLAVE]    │◄────►│  [TEE ENCLAVE]  │                     │  ║
//! ║     │  │  UAE Sovereignty  │      │  MAS Zone       │                     │  ║
//! ║     │  └───────────────────┘      └─────────────────┘                     │  ║
//! ║     │         ▲                                                           │  ║
//! ║     │         │ DATA ORIGIN                                               │  ║
//! ║     │         🔒                                                          │  ║
//! ║     │                                                                     │  ║
//! ║     └─────────────────────────────────────────────────────────────────────┘  ║
//! ║                                                                               ║
//! ║  LEGEND:                                                                      ║
//! ║  ⬡ Data Center    [TEE] Secure Enclave    ✅ Allowed    ❌ Blocked         ║
//! ║  ──► Data Flow    ╳╳╳ Blocked Path         🔒 Data Origin                   ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::core::{CloudProvider, Jurisdiction};

// ============================================================================
// Geographic Regions
// ============================================================================

/// A geographic region with regulatory zone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    /// Region code (ISO 3166-1)
    pub code: String,
    /// Display name
    pub name: String,
    /// Flag emoji
    pub flag: String,
    /// Regulatory zone
    pub zone: RegulatoryZone,
    /// Data centers in this region
    pub data_centers: Vec<DataCenter>,
    /// Map coordinates (for visualization)
    pub coordinates: MapCoordinates,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegulatoryZone {
    /// European Union (GDPR)
    EU,
    /// Gulf Cooperation Council
    GCC,
    /// United States
    US,
    /// Asia Pacific
    APAC,
    /// Switzerland
    Swiss,
    /// United Kingdom (post-Brexit)
    UK,
    /// China
    China,
    /// Russia
    Russia,
    /// Unregulated
    Unregulated,
}

impl RegulatoryZone {
    pub fn display_name(&self) -> &'static str {
        match self {
            RegulatoryZone::EU => "GDPR Zone",
            RegulatoryZone::GCC => "GCC Data Sovereignty",
            RegulatoryZone::US => "US Regulatory",
            RegulatoryZone::APAC => "APAC",
            RegulatoryZone::Swiss => "Swiss Banking",
            RegulatoryZone::UK => "UK GDPR",
            RegulatoryZone::China => "China Data Localization",
            RegulatoryZone::Russia => "Russia Data Localization",
            RegulatoryZone::Unregulated => "Unregulated",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            RegulatoryZone::EU => "#0052B4",
            RegulatoryZone::GCC => "#00732F",
            RegulatoryZone::US => "#B22234",
            RegulatoryZone::APAC => "#FF6B00",
            RegulatoryZone::Swiss => "#FF0000",
            RegulatoryZone::UK => "#012169",
            RegulatoryZone::China => "#DE2910",
            RegulatoryZone::Russia => "#0039A6",
            RegulatoryZone::Unregulated => "#888888",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCoordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// A data center
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCenter {
    /// Data center ID
    pub id: String,
    /// Display name
    pub name: String,
    /// City
    pub city: String,
    /// Provider
    pub provider: CloudProvider,
    /// Has TEE capability
    pub has_tee: bool,
    /// TEE types available
    pub tee_types: Vec<TEEType>,
    /// Current load (0-100)
    pub load: u8,
    /// Status
    pub status: DataCenterStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TEEType {
    IntelSGX,
    AMDSEV,
    AWSNitro,
    ArmTrustZone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataCenterStatus {
    Online,
    Degraded,
    Offline,
    Maintenance,
}

// ============================================================================
// Data Flow
// ============================================================================

/// A data flow between locations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    /// Flow ID
    pub id: String,
    /// Source location
    pub source: FlowEndpoint,
    /// Destination location
    pub destination: FlowEndpoint,
    /// Data type
    pub data_type: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Flow status
    pub status: FlowStatus,
    /// Violation (if blocked)
    pub violation: Option<String>,
    /// Timestamp
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEndpoint {
    /// Region code
    pub region: String,
    /// Data center ID
    pub data_center: Option<String>,
    /// Is TEE enclave
    pub is_tee: bool,
    /// Display name
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowStatus {
    /// Flow is active
    Active,
    /// Flow completed
    Completed,
    /// Flow blocked by regulation
    Blocked,
    /// Flow pending approval
    Pending,
}

// ============================================================================
// Sovereignty Visualizer
// ============================================================================

/// The Sovereign Border Visualizer
pub struct SovereignBorderVisualizer {
    /// Regions
    regions: HashMap<String, Region>,
    /// Active data flows
    flows: Vec<DataFlow>,
    /// Current jurisdiction mode
    jurisdiction: Jurisdiction,
    /// Allowed routes
    allowed_routes: HashMap<(String, String), bool>,
}

impl SovereignBorderVisualizer {
    pub fn new() -> Self {
        let regions = Self::initialize_regions();
        let allowed_routes = HashMap::new();

        SovereignBorderVisualizer {
            regions,
            flows: Vec::new(),
            jurisdiction: Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer: true,
                require_local_storage: true,
            },
            allowed_routes,
        }
    }

    fn initialize_regions() -> HashMap<String, Region> {
        let mut regions = HashMap::new();

        // UAE
        regions.insert(
            "AE".to_string(),
            Region {
                code: "AE".to_string(),
                name: "United Arab Emirates".to_string(),
                flag: "🇦🇪".to_string(),
                zone: RegulatoryZone::GCC,
                data_centers: vec![
                    DataCenter {
                        id: "AE-AD-01".to_string(),
                        name: "Aethelred Abu Dhabi".to_string(),
                        city: "Abu Dhabi".to_string(),
                        provider: CloudProvider::Aethelred,
                        has_tee: true,
                        tee_types: vec![TEEType::IntelSGX, TEEType::AMDSEV],
                        load: 45,
                        status: DataCenterStatus::Online,
                    },
                    DataCenter {
                        id: "AE-DXB-01".to_string(),
                        name: "AWS Dubai".to_string(),
                        city: "Dubai".to_string(),
                        provider: CloudProvider::AWS,
                        has_tee: true,
                        tee_types: vec![TEEType::AWSNitro],
                        load: 62,
                        status: DataCenterStatus::Online,
                    },
                ],
                coordinates: MapCoordinates {
                    latitude: 24.4539,
                    longitude: 54.3773,
                },
            },
        );

        // Singapore
        regions.insert(
            "SG".to_string(),
            Region {
                code: "SG".to_string(),
                name: "Singapore".to_string(),
                flag: "🇸🇬".to_string(),
                zone: RegulatoryZone::APAC,
                data_centers: vec![DataCenter {
                    id: "SG-01".to_string(),
                    name: "AWS Singapore".to_string(),
                    city: "Singapore".to_string(),
                    provider: CloudProvider::AWS,
                    has_tee: true,
                    tee_types: vec![TEEType::AWSNitro, TEEType::IntelSGX],
                    load: 78,
                    status: DataCenterStatus::Online,
                }],
                coordinates: MapCoordinates {
                    latitude: 1.3521,
                    longitude: 103.8198,
                },
            },
        );

        // Germany (EU)
        regions.insert(
            "DE".to_string(),
            Region {
                code: "DE".to_string(),
                name: "Germany".to_string(),
                flag: "🇩🇪".to_string(),
                zone: RegulatoryZone::EU,
                data_centers: vec![DataCenter {
                    id: "DE-FRA-01".to_string(),
                    name: "AWS Frankfurt".to_string(),
                    city: "Frankfurt".to_string(),
                    provider: CloudProvider::AWS,
                    has_tee: true,
                    tee_types: vec![TEEType::AWSNitro],
                    load: 55,
                    status: DataCenterStatus::Online,
                }],
                coordinates: MapCoordinates {
                    latitude: 50.1109,
                    longitude: 8.6821,
                },
            },
        );

        // USA
        regions.insert(
            "US".to_string(),
            Region {
                code: "US".to_string(),
                name: "United States".to_string(),
                flag: "🇺🇸".to_string(),
                zone: RegulatoryZone::US,
                data_centers: vec![
                    DataCenter {
                        id: "US-VA-01".to_string(),
                        name: "AWS Virginia".to_string(),
                        city: "Ashburn".to_string(),
                        provider: CloudProvider::AWS,
                        has_tee: true,
                        tee_types: vec![TEEType::AWSNitro],
                        load: 82,
                        status: DataCenterStatus::Online,
                    },
                    DataCenter {
                        id: "US-CA-01".to_string(),
                        name: "GCP California".to_string(),
                        city: "San Jose".to_string(),
                        provider: CloudProvider::GCP,
                        has_tee: true,
                        tee_types: vec![TEEType::IntelSGX, TEEType::AMDSEV],
                        load: 71,
                        status: DataCenterStatus::Online,
                    },
                ],
                coordinates: MapCoordinates {
                    latitude: 37.0902,
                    longitude: -95.7129,
                },
            },
        );

        // Switzerland
        regions.insert(
            "CH".to_string(),
            Region {
                code: "CH".to_string(),
                name: "Switzerland".to_string(),
                flag: "🇨🇭".to_string(),
                zone: RegulatoryZone::Swiss,
                data_centers: vec![DataCenter {
                    id: "CH-ZH-01".to_string(),
                    name: "Swiss Data Center".to_string(),
                    city: "Zurich".to_string(),
                    provider: CloudProvider::OnPremise,
                    has_tee: true,
                    tee_types: vec![TEEType::IntelSGX],
                    load: 35,
                    status: DataCenterStatus::Online,
                }],
                coordinates: MapCoordinates {
                    latitude: 46.8182,
                    longitude: 8.2275,
                },
            },
        );

        // Saudi Arabia (GCC)
        regions.insert(
            "SA".to_string(),
            Region {
                code: "SA".to_string(),
                name: "Saudi Arabia".to_string(),
                flag: "🇸🇦".to_string(),
                zone: RegulatoryZone::GCC,
                data_centers: vec![DataCenter {
                    id: "SA-RUH-01".to_string(),
                    name: "STC Riyadh".to_string(),
                    city: "Riyadh".to_string(),
                    provider: CloudProvider::OnPremise,
                    has_tee: false,
                    tee_types: vec![],
                    load: 40,
                    status: DataCenterStatus::Online,
                }],
                coordinates: MapCoordinates {
                    latitude: 23.8859,
                    longitude: 45.0792,
                },
            },
        );

        regions
    }

    /// Add a data flow
    pub fn add_flow(&mut self, flow: DataFlow) {
        self.flows.push(flow);
    }

    /// Simulate a data transfer and visualize
    pub fn simulate_transfer(
        &mut self,
        from_region: &str,
        from_dc: Option<&str>,
        to_region: &str,
        to_dc: Option<&str>,
        data_type: &str,
        size_bytes: u64,
    ) -> DataFlow {
        let source_region = self.regions.get(from_region);
        let dest_region = self.regions.get(to_region);

        let source = FlowEndpoint {
            region: from_region.to_string(),
            data_center: from_dc.map(String::from),
            is_tee: source_region
                .and_then(|r| r.data_centers.first())
                .map(|dc| dc.has_tee)
                .unwrap_or(false),
            display_name: source_region
                .map(|r| format!("{} {}", r.flag, r.name))
                .unwrap_or_else(|| from_region.to_string()),
        };

        let destination = FlowEndpoint {
            region: to_region.to_string(),
            data_center: to_dc.map(String::from),
            is_tee: dest_region
                .and_then(|r| r.data_centers.first())
                .map(|dc| dc.has_tee)
                .unwrap_or(false),
            display_name: dest_region
                .map(|r| format!("{} {}", r.flag, r.name))
                .unwrap_or_else(|| to_region.to_string()),
        };

        // Check if transfer is allowed
        let (status, violation) = self.check_transfer_allowed(from_region, to_region);

        let flow = DataFlow {
            id: format!("flow-{}", uuid::Uuid::new_v4()),
            source,
            destination,
            data_type: data_type.to_string(),
            size_bytes,
            status,
            violation,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.flows.push(flow.clone());
        flow
    }

    fn check_transfer_allowed(&self, from: &str, to: &str) -> (FlowStatus, Option<String>) {
        if from == to {
            return (FlowStatus::Active, None);
        }

        match &self.jurisdiction {
            Jurisdiction::WildWest => (FlowStatus::Active, None),

            Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer, ..
            } => {
                if from == "AE" {
                    let gcc_countries = ["AE", "SA", "KW", "QA", "BH", "OM"];
                    if *allow_gcc_transfer && gcc_countries.contains(&to) {
                        (FlowStatus::Active, None)
                    } else if to == "SG" || to == "CH" {
                        // Approved jurisdictions
                        (FlowStatus::Active, None)
                    } else {
                        (
                            FlowStatus::Blocked,
                            Some(format!(
                                "UAE Data Sovereignty: Transfer to {} blocked. \
                             Data must remain within UAE or approved jurisdictions.",
                                to
                            )),
                        )
                    }
                } else {
                    (FlowStatus::Active, None)
                }
            }

            Jurisdiction::GDPRStrict {
                allow_adequacy_countries,
            } => {
                let eu_countries = ["DE", "FR", "IT", "ES", "NL", "BE", "AT", "PL"];
                let adequate_countries = ["CH", "GB", "JP", "KR", "NZ", "CA"];

                if eu_countries.contains(&from) {
                    if eu_countries.contains(&to) {
                        (FlowStatus::Active, None)
                    } else if *allow_adequacy_countries && adequate_countries.contains(&to) {
                        (FlowStatus::Active, None)
                    } else {
                        (
                            FlowStatus::Blocked,
                            Some(format!(
                            "GDPR Article 44: Transfer to {} (non-adequate jurisdiction) blocked.",
                            to
                        )),
                        )
                    }
                } else {
                    (FlowStatus::Active, None)
                }
            }

            _ => (FlowStatus::Active, None),
        }
    }

    /// Generate ASCII map
    pub fn generate_map(&self) -> String {
        let mut map = String::new();

        map.push_str(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    🌍 SOVEREIGN BORDER VISUALIZER                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║                           WORLD DATA FLOW MAP                                 ║
║                                                                               ║
"#,
        );

        // Draw regions
        map.push_str(
            r#"║     ┌─────────────────────────────────────────────────────────────────────┐  ║
║     │                                                                     │  ║
"#,
        );

        // EU Section
        if let Some(de) = self.regions.get("DE") {
            map.push_str(&format!(
                "║     │              {} {}                                          │  ║\n",
                de.flag,
                de.zone.display_name()
            ));
            for dc in &de.data_centers {
                let tee_marker = if dc.has_tee { "[TEE]" } else { "" };
                map.push_str(&format!(
                    "║     │              ⬡ {} {} ({})                            │  ║\n",
                    dc.city,
                    tee_marker,
                    dc.status == DataCenterStatus::Online
                ));
            }
        }

        map.push_str(
            "║     │                                                                     │  ║\n",
        );

        // UAE and Singapore
        if let (Some(ae), Some(sg)) = (self.regions.get("AE"), self.regions.get("SG")) {
            map.push_str(&format!(
                "║     │   {} UAE                           {} SINGAPORE               │  ║\n",
                ae.flag, sg.flag
            ));
            map.push_str(
                "║     │   ┌───────────────────┐           ┌─────────────────┐          │  ║\n",
            );

            // UAE data centers
            for dc in &ae.data_centers {
                map.push_str(&format!(
                    "║     │   │ {} ⬡               │           │                 │          │  ║\n",
                    dc.city
                ));
                if dc.has_tee {
                    map.push_str("║     │   │  [TEE ENCLAVE]      │◄─────────►│  [TEE ENCLAVE]  │          │  ║\n");
                }
            }

            map.push_str(&format!(
                "║     │   │  {}   │           │  MAS Zone       │          │  ║\n",
                ae.zone.display_name()
            ));
            map.push_str(
                "║     │   └───────────────────┘           └─────────────────┘          │  ║\n",
            );
        }

        map.push_str(
            "║     │                                                                     │  ║\n",
        );

        // USA Section
        if let Some(us) = self.regions.get("US") {
            map.push_str(&format!(
                "║     │   {} {}                                                    │  ║\n",
                us.flag,
                us.zone.display_name()
            ));
            for dc in &us.data_centers {
                map.push_str(&format!(
                    "║     │   ⬡ {} ({})                                               │  ║\n",
                    dc.city,
                    if dc.status == DataCenterStatus::Online {
                        "Online"
                    } else {
                        "Offline"
                    }
                ));
            }
        }

        map.push_str(
            r#"║     │                                                                     │  ║
║     └─────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
"#,
        );

        // Active flows section
        map.push_str(
            "╠═══════════════════════════════════════════════════════════════════════════════╣\n",
        );
        map.push_str(
            "║  ACTIVE DATA FLOWS                                                            ║\n",
        );
        map.push_str(
            "╠═══════════════════════════════════════════════════════════════════════════════╣\n",
        );

        let recent_flows: Vec<_> = self.flows.iter().rev().take(5).collect();
        if recent_flows.is_empty() {
            map.push_str("║  No active data flows.                                                         ║\n");
        } else {
            for flow in recent_flows {
                let status_icon = match flow.status {
                    FlowStatus::Active => "→→→",
                    FlowStatus::Completed => "✅",
                    FlowStatus::Blocked => "❌",
                    FlowStatus::Pending => "⏳",
                };
                map.push_str(&format!(
                    "║  {} {} {} {} ({})           ║\n",
                    flow.source.display_name,
                    status_icon,
                    flow.destination.display_name,
                    Self::format_size(flow.size_bytes),
                    flow.data_type
                ));
                if let Some(violation) = &flow.violation {
                    map.push_str(&format!(
                        "║     ⚠️  {}  ║\n",
                        violation.chars().take(60).collect::<String>()
                    ));
                }
            }
        }

        map.push_str(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  LEGEND                                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ⬡ Data Center    [TEE] Secure Enclave    ✅ Allowed    ❌ Blocked          ║
║  →→→ Active Flow    ⏳ Pending             🔒 Encrypted                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        map
    }

    fn format_size(bytes: u64) -> String {
        if bytes >= 1_000_000_000 {
            format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
        } else if bytes >= 1_000_000 {
            format!("{:.1} MB", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.1} KB", bytes as f64 / 1_000.0)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Set jurisdiction for visualization
    pub fn set_jurisdiction(&mut self, jurisdiction: Jurisdiction) {
        self.jurisdiction = jurisdiction;
        // Recalculate allowed routes
        self.recalculate_routes();
    }

    fn recalculate_routes(&mut self) {
        self.allowed_routes.clear();
        let region_codes: Vec<_> = self.regions.keys().cloned().collect();

        for from in &region_codes {
            for to in &region_codes {
                if from != to {
                    let (status, _) = self.check_transfer_allowed(from, to);
                    self.allowed_routes
                        .insert((from.clone(), to.clone()), status == FlowStatus::Active);
                }
            }
        }
    }

    /// Get route matrix
    pub fn get_route_matrix(&self) -> String {
        let regions = ["AE", "SG", "DE", "US", "CH", "SA"];
        let mut matrix = String::new();

        matrix.push_str("\n     │");
        for r in &regions {
            matrix.push_str(&format!("  {:>3} │", r));
        }
        matrix.push_str("\n─────┼");
        for _ in &regions {
            matrix.push_str("──────┼");
        }
        matrix.push('\n');

        for from in &regions {
            matrix.push_str(&format!(" {:>3} │", from));
            for to in &regions {
                if from == to {
                    matrix.push_str("   ●  │");
                } else {
                    let key = (from.to_string(), to.to_string());
                    let allowed = self.allowed_routes.get(&key).copied().unwrap_or(true);
                    let symbol = if allowed { "  ✅  " } else { "  ❌  " };
                    matrix.push_str(&format!("{}│", symbol));
                }
            }
            matrix.push('\n');
        }

        matrix
    }
}

impl Default for SovereignBorderVisualizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uae_to_gcc_allowed() {
        let mut viz = SovereignBorderVisualizer::new();
        viz.set_jurisdiction(Jurisdiction::UAEDataSovereignty {
            allow_gcc_transfer: true,
            require_local_storage: true,
        });

        let flow = viz.simulate_transfer("AE", None, "SA", None, "Financial", 1000);
        assert_eq!(flow.status, FlowStatus::Active);
    }

    #[test]
    fn test_uae_to_us_blocked() {
        let mut viz = SovereignBorderVisualizer::new();
        viz.set_jurisdiction(Jurisdiction::UAEDataSovereignty {
            allow_gcc_transfer: true,
            require_local_storage: true,
        });

        let flow = viz.simulate_transfer("AE", None, "US", None, "Financial", 1000);
        assert_eq!(flow.status, FlowStatus::Blocked);
    }

    #[test]
    fn test_gdpr_eu_to_eu_allowed() {
        let mut viz = SovereignBorderVisualizer::new();
        viz.set_jurisdiction(Jurisdiction::GDPRStrict {
            allow_adequacy_countries: true,
        });

        let flow = viz.simulate_transfer("DE", None, "FR", None, "PII", 1000);
        assert_eq!(flow.status, FlowStatus::Active);
    }
}

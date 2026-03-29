//! Trade Finance Demo
//!
//! This example demonstrates the UAE-Singapore trade settlement scenario
//! using the Infinity Sandbox.

use aethelred_sandbox::*;

fn main() {
    println!("{}", InfinitySandbox::welcome_message());

    // Create sandbox
    let sandbox = InfinitySandbox::default();

    // Create a session
    let owner = ParticipantId("fab-user-1".to_string());
    let session_id = sandbox
        .create_session(
            owner.clone(),
            "Mohammed Al-Rashid".to_string(),
            "First Abu Dhabi Bank".to_string(),
        )
        .unwrap();

    println!("\n✅ Session created: {}", session_id.0);

    // Set jurisdiction to UAE Data Sovereignty
    sandbox
        .set_jurisdiction(
            &session_id,
            Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer: true,
                require_local_storage: true,
            },
        )
        .unwrap();

    println!("📋 Jurisdiction set: UAE Data Sovereignty");

    // Set hardware target
    sandbox
        .set_hardware_target(
            &session_id,
            HardwareTarget::IntelSGX {
                location: DataCenterLocation {
                    country: "AE".to_string(),
                    city: "Abu Dhabi".to_string(),
                    provider: CloudProvider::Aethelred,
                    dc_id: Some("AD-01".to_string()),
                },
                svn: 15,
            },
        )
        .unwrap();

    println!("🖥️  Hardware target: Intel SGX (Abu Dhabi)");

    // Test data transfer
    let mut visualizer = SovereignBorderVisualizer::new();
    visualizer.set_jurisdiction(Jurisdiction::UAEDataSovereignty {
        allow_gcc_transfer: true,
        require_local_storage: true,
    });

    // Simulate transfers
    println!("\n📊 Testing Data Transfers:\n");

    // UAE to Singapore (allowed)
    let flow = visualizer.simulate_transfer("AE", None, "SG", None, "Financial", 1_000_000);
    println!("  AE → SG: {:?}", flow.status);

    // UAE to USA (blocked)
    let flow = visualizer.simulate_transfer("AE", None, "US", None, "Financial", 1_000_000);
    println!(
        "  AE → US: {:?} - {}",
        flow.status,
        flow.violation.unwrap_or_default()
    );

    // UAE to Saudi (allowed - GCC)
    let flow = visualizer.simulate_transfer("AE", None, "SA", None, "Financial", 1_000_000);
    println!("  AE → SA: {:?}", flow.status);

    println!("{}", visualizer.generate_map());

    // Estimate costs
    let profiler = AIGasProfiler::new();
    let model = ModelSpec::credit_scoring();
    let hardware = HardwareTarget::IntelSGX {
        location: DataCenterLocation {
            country: "AE".to_string(),
            city: "Abu Dhabi".to_string(),
            provider: CloudProvider::Aethelred,
            dc_id: Some("AD-01".to_string()),
        },
        svn: 15,
    };

    let estimate = profiler.estimate(&model, &hardware, 1000);
    println!("{}", profiler.generate_report(&estimate));

    println!("\n🎉 Trade Finance Demo Complete!");
}

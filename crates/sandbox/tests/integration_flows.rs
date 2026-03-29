use std::sync::{Mutex, OnceLock};

use aethelred_sandbox::{
    AIGasProfiler, CloudProvider, DataCenterLocation, HardwareRuntime, HardwareTarget,
    InfinitySandbox, Jurisdiction, ModelSpec, ParticipantId, ScenarioLibrary,
};

fn sgx_abu_dhabi() -> HardwareTarget {
    HardwareTarget::IntelSGX {
        location: DataCenterLocation {
            country: "AE".to_string(),
            city: "Abu Dhabi".to_string(),
            provider: CloudProvider::Aethelred,
            dc_id: Some("AD-01".to_string()),
        },
        svn: 15,
    }
}

#[test]
fn session_runtime_profiler_integration_flow() {
    let sandbox = InfinitySandbox::default();
    let session_id = sandbox
        .create_session(
            ParticipantId("owner-1".to_string()),
            "Owner".to_string(),
            "Aethelred".to_string(),
        )
        .expect("session should be created");

    let target = sgx_abu_dhabi();
    sandbox
        .set_jurisdiction(
            &session_id,
            Jurisdiction::UAEDataSovereignty {
                allow_gcc_transfer: true,
                require_local_storage: true,
            },
        )
        .expect("jurisdiction update should succeed");
    sandbox
        .set_hardware_target(&session_id, target.clone())
        .expect("hardware update should succeed");

    let mut runtime = HardwareRuntime::new();
    runtime
        .select_target(target.clone())
        .expect("runtime target selection should succeed");
    let execution = runtime
        .simulate_execution(0.75, true)
        .expect("TEE execution should succeed");
    assert!(execution.attestation.is_some());

    let profiler = AIGasProfiler::new();
    let estimate = profiler.estimate(&ModelSpec::credit_scoring(), &target, 512);
    assert!(estimate.breakdown.total_aethel > 0.0);
    assert_eq!(estimate.cloud_comparisons.len(), 3);

    let session = sandbox
        .get_session(&session_id)
        .expect("session should still exist");
    assert!(session.logs.len() >= 3);
}

#[test]
fn scenario_library_runtime_compatibility_flow() {
    let library = ScenarioLibrary::new();
    let scenario = library
        .get("credit_scoring")
        .expect("default scenario should exist");
    assert!(!scenario.workflow.is_empty());
    assert!(!scenario.test_cases.is_empty());

    let mut runtime = HardwareRuntime::new();
    runtime
        .select_target(HardwareTarget::GenericCPU)
        .expect("generic cpu target should exist");
    let execution = runtime
        .simulate_execution(0.25, false)
        .expect("execution should succeed");
    assert!((execution.cost_aethel - 0.0025).abs() < 1e-12);
}

#[test]
fn profiler_can_load_cloud_pricing_from_env() {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("env lock poisoned");

    std::env::set_var(
        "AETHELRED_SANDBOX_CLOUD_PRICING_JSON",
        r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.77,
                "neural_network_cost_per_100": 0.77,
                "transformer_cost_per_100": 0.77,
                "default_cost_per_100": 0.77,
                "tee_overhead_multiplier": 0.0
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#,
    );

    let profiler = AIGasProfiler::try_new_from_env().expect("env config should parse");
    let estimate = profiler.estimate(
        &ModelSpec::credit_scoring(),
        &HardwareTarget::GenericCPU,
        100,
    );
    let aws = estimate
        .cloud_comparisons
        .iter()
        .find(|c| c.provider == "AWS SageMaker")
        .expect("aws comparison missing");
    assert!((aws.cost_usd - 0.77).abs() < 1e-9);

    std::env::remove_var("AETHELRED_SANDBOX_CLOUD_PRICING_JSON");
}

#[test]
fn profiler_prefers_cloud_pricing_file_from_env() {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("env lock poisoned");

    let mut file_path = std::env::temp_dir();
    file_path.push(format!(
        "aethelred_cloud_pricing_it_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos()
    ));

    std::fs::write(
        &file_path,
        r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.88,
                "neural_network_cost_per_100": 0.88,
                "transformer_cost_per_100": 0.88,
                "default_cost_per_100": 0.88,
                "tee_overhead_multiplier": 0.0
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#,
    )
    .expect("pricing file write should succeed");

    std::env::set_var("AETHELRED_SANDBOX_CLOUD_PRICING_FILE", &file_path);
    std::env::set_var(
        "AETHELRED_SANDBOX_CLOUD_PRICING_JSON",
        r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.44,
                "neural_network_cost_per_100": 0.44,
                "transformer_cost_per_100": 0.44,
                "default_cost_per_100": 0.44,
                "tee_overhead_multiplier": 0.0
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#,
    );

    let profiler = AIGasProfiler::try_new_from_env().expect("env config should parse");
    let estimate = profiler.estimate(
        &ModelSpec::credit_scoring(),
        &HardwareTarget::GenericCPU,
        100,
    );
    let aws = estimate
        .cloud_comparisons
        .iter()
        .find(|c| c.provider == "AWS SageMaker")
        .expect("aws comparison missing");
    assert!((aws.cost_usd - 0.88).abs() < 1e-9);

    std::env::remove_var("AETHELRED_SANDBOX_CLOUD_PRICING_FILE");
    std::env::remove_var("AETHELRED_SANDBOX_CLOUD_PRICING_JSON");
    let _ = std::fs::remove_file(file_path);
}

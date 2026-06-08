//! Product workflow E2E tests using the reusable guardian/child harness.
//!
//! This mirrors docs/design/app-pairing-and-regions.md: the guardian app chooses
//! one backend, logs in, creates a pairing code; the child app enrolls on the
//! same backend with a stable device id; alerts then stream only to the guardian
//! session for that backend, and decisions use that session token.

mod support;

use bulwark_proto::v1::{Category, ReviewDecision};
use support::workflow::{ChildApp, GuardianApp, WorkflowServer};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guardian_child_workflow_delivers_alert_and_applies_decision() {
    let server = WorkflowServer::spawn().await;

    let mut guardian = GuardianApp::connect(&server).await;
    guardian
        .create_account_and_login("guardian@workflow.test", "password123", "Guardian")
        .await;

    let pair = guardian.create_pair_code("Workflow Kid").await;
    assert!(!pair.code.is_empty());
    assert!(pair.expires_ts > 0);

    let mut child = ChildApp::connect(&server, "workflow-device-1").await;
    let enrollment = child.enroll(&pair.code).await;
    assert_eq!(enrollment.device_id, child.device_id());

    let children = guardian.list_children().await;
    assert!(children.children.iter().any(|c| {
        c.child_id == enrollment.child_id
            && c.family_id == enrollment.family_id
            && c.device_id == enrollment.device_id
            && c.child_name == "Workflow Kid"
    }));

    let mut stream = guardian.open_reviews().await;
    let ack = server
        .raise_alert_for_child("workflow-alert-1", child.enrollment(), Category::AdultImage)
        .await;
    assert_eq!(ack.alert_id, "workflow-alert-1");
    assert!(ack.delivered);

    let alert = GuardianApp::next_review(&mut stream, "guardian review stream").await;
    assert_eq!(alert.alert_id, "workflow-alert-1");
    assert_eq!(alert.child_id, enrollment.child_id);
    assert_eq!(alert.family_id, enrollment.family_id);
    assert_eq!(alert.device_id, enrollment.device_id);

    let decision = guardian
        .submit_decision(&alert.alert_id, &alert.device_id, ReviewDecision::Approve)
        .await;
    assert_eq!(decision.alert_id, "workflow-alert-1");
    assert!(decision.applied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workflow_requires_new_session_and_enrollment_after_server_switch() {
    let london = WorkflowServer::spawn().await;
    let us = WorkflowServer::spawn().await;

    let mut london_guardian = GuardianApp::connect(&london).await;
    let london_token = london_guardian
        .create_account_and_login("guardian@workflow.test", "password123", "Guardian UK")
        .await;
    let london_pair = london_guardian.create_pair_code("London Kid").await;

    let us_child_with_london_code = ChildApp::connect(&us, "cross-region-device").await;
    let redeem_err = us_child_with_london_code
        .try_enroll(&london_pair.code)
        .await
        .expect_err("London pair code must not redeem on another backend");
    assert_eq!(redeem_err.code(), tonic::Code::NotFound);

    let us_guardian_with_london_token = GuardianApp::connect_with_token(&us, london_token).await;
    let create_err = us_guardian_with_london_token
        .try_create_pair_code("Wrong Backend Kid")
        .await
        .expect_err("London token must not authenticate to another backend");
    assert_eq!(create_err.code(), tonic::Code::Unauthenticated);

    let mut us_guardian = GuardianApp::connect(&us).await;
    us_guardian
        .create_account_and_login("guardian@workflow.test", "password123", "Guardian US")
        .await;
    let us_pair = us_guardian.create_pair_code("US Kid").await;
    let mut us_child = ChildApp::connect(&us, "us-workflow-device").await;
    let us_enrollment = us_child.enroll(&us_pair.code).await;
    assert!(!us_enrollment.child_id.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workflow_rejects_reused_pair_codes_and_duplicate_device_ids() {
    let server = WorkflowServer::spawn().await;

    let mut guardian = GuardianApp::connect(&server).await;
    guardian
        .create_account_and_login("guardian@workflow.test", "password123", "Guardian")
        .await;

    let first_pair = guardian.create_pair_code("First Kid").await;
    let mut first_child = ChildApp::connect(&server, "stable-device-1").await;
    let first_enrollment = first_child.enroll(&first_pair.code).await;
    assert_eq!(first_enrollment.device_id, "stable-device-1");

    let second_child = ChildApp::connect(&server, "stable-device-2").await;
    let reuse_err = second_child
        .try_enroll(&first_pair.code)
        .await
        .expect_err("pair code must be single-use");
    assert_eq!(reuse_err.code(), tonic::Code::NotFound);

    let second_pair = guardian.create_pair_code("Second Kid").await;
    let duplicate_device = ChildApp::connect(&server, "stable-device-1").await;
    let duplicate_err = duplicate_device
        .try_enroll(&second_pair.code)
        .await
        .expect_err("a stable device_id must link to only one child");
    assert_eq!(duplicate_err.code(), tonic::Code::AlreadyExists);
}

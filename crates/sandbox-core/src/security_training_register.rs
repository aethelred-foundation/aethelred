//! Mandatory security-training register.
//!
//! Maps to **ISO 27001 A.7.2.2** (information security awareness,
//! education and training), **SOC 2 CC1.4** (commitment to competence),
//! **NIST 800-53 AT-2** (security awareness training), **HIPAA
//! §164.530(b)** (workforce training), and PCI-DSS 12.6. Every employee
//! must complete required security training on a documented cadence
//! (typically annual), with completion evidence retained for audit.
//!
//! Two-level model:
//!
//! - **[`Course`]** — one defined training module (e.g., "Annual
//!   Security Awareness 2025", "HIPAA Privacy 101"). Courses have a
//!   recurrence cadence and a passing threshold.
//! - **[`Enrollment`]** — one (subject, course) pair with progress
//!   through the lifecycle `Assigned → InProgress → Completed | Failed
//!   | Exempt | Withdrawn`.
//!
//! The registry exposes `due_for_renewal(now)` (subjects whose latest
//! completion is older than the course cadence) and `incomplete(now)`
//! (assignments not yet completed by the deadline).
//!
//! Distinct from [`crate::access_certification`] (logical access
//! review) and [`crate::background_check_register`] (pre-employment
//! screening); this is the **ongoing competence** evidence.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// CourseKind
// =============================================================================

/// Domain of the training course.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CourseKind {
    /// General security awareness.
    SecurityAwareness,
    /// Privacy / GDPR.
    Privacy,
    /// HIPAA workforce training.
    Hipaa,
    /// PCI-DSS handling.
    Pci,
    /// Anti-bribery / FCPA.
    AntiBribery,
    /// Anti-money-laundering.
    Aml,
    /// Code of conduct.
    CodeOfConduct,
    /// Insider-threat awareness.
    InsiderThreat,
    /// AI / model-risk responsibility.
    AiResponsibility,
    /// Role-specific (free-form).
    RoleSpecific,
}

// =============================================================================
// EnrollmentStage
// =============================================================================

/// Per-enrollment lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStage {
    /// Assigned to the subject.
    Assigned,
    /// Subject started the course.
    InProgress,
    /// Subject completed and passed.
    Completed,
    /// Subject completed but did not pass.
    Failed,
    /// Subject was exempted (e.g., on leave).
    Exempt,
    /// Withdrawn / cancelled before completion.
    Withdrawn,
}

impl EnrollmentStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Exempt | Self::Withdrawn
        )
    }

    /// True if completion satisfies the course requirement.
    pub fn is_satisfying(self) -> bool {
        matches!(self, Self::Completed | Self::Exempt)
    }
}

// =============================================================================
// Course
// =============================================================================

/// One training course definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Course {
    /// Stable course id (e.g., "SEC-AWARENESS-2025").
    pub course_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Course kind.
    pub kind: CourseKind,
    /// Description.
    pub description: String,
    /// Owner / training team.
    pub owner: String,
    /// Recurrence cadence in days (0 = one-time, no recurrence).
    pub recurrence_days: u32,
    /// Passing threshold (0-100; ignored if course is pass/fail).
    pub passing_score_pct: u8,
    /// True if course is currently active (assignable).
    pub active: bool,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Course {
    /// Construct a new active course.
    pub fn new(
        course_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        kind: CourseKind,
        description: impl Into<String>,
        owner: impl Into<String>,
        recurrence_days: u32,
        passing_score_pct: u8,
    ) -> Self {
        Self {
            course_id: course_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            kind,
            description: description.into(),
            owner: owner.into(),
            recurrence_days,
            passing_score_pct: passing_score_pct.min(100),
            active: true,
            tags: Vec::new(),
        }
    }
}

// =============================================================================
// Enrollment
// =============================================================================

/// One subject's enrollment in a course.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    /// Stable enrollment id.
    pub enrollment_id: String,
    /// Tenant scope (mirrors course's tenant).
    pub tenant_id: String,
    /// Course id.
    pub course_id: String,
    /// Subject id.
    pub subject_id: String,
    /// Subject display name.
    pub subject_name: String,
    /// Stage.
    pub stage: EnrollmentStage,
    /// Score (0-100), recorded on completion.
    pub score_pct: Option<u8>,
    /// RFC 3339 — assigned.
    pub assigned_at: String,
    /// RFC 3339 — due (deadline).
    pub due_at: Option<String>,
    /// RFC 3339 — started.
    pub started_at: Option<String>,
    /// RFC 3339 — completed (terminal).
    pub completed_at: Option<String>,
    /// Optional certificate / evidence URI.
    pub certificate_uri: Option<String>,
    /// Free-text note.
    pub note: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Enrollment {
    /// New `Assigned` enrollment.
    pub fn new(
        enrollment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        course_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_name: impl Into<String>,
        assigned_at: impl Into<String>,
    ) -> Self {
        Self {
            enrollment_id: enrollment_id.into(),
            tenant_id: tenant_id.into(),
            course_id: course_id.into(),
            subject_id: subject_id.into(),
            subject_name: subject_name.into(),
            stage: EnrollmentStage::Assigned,
            score_pct: None,
            assigned_at: assigned_at.into(),
            due_at: None,
            started_at: None,
            completed_at: None,
            certificate_uri: None,
            note: None,
            tags: Vec::new(),
        }
    }

    /// True if `now >= due_at` and the enrollment is non-terminal.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match self.due_at.as_deref() {
            Some(d) => now >= d,
            None => false,
        }
    }
}

fn legal_transition(from: EnrollmentStage, to: EnrollmentStage) -> bool {
    use EnrollmentStage::*;
    matches!(
        (from, to),
        (Assigned, InProgress)
            | (Assigned, Exempt)
            | (Assigned, Withdrawn)
            | (InProgress, Completed)
            | (InProgress, Failed)
            | (InProgress, Withdrawn)
            | (Failed, InProgress) // re-attempt
    )
}

fn age_in_days(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// SecurityTrainingRegister
// =============================================================================

/// Thread-safe registry of training courses + enrollments.
#[derive(Debug, Default)]
pub struct SecurityTrainingRegister {
    courses: RwLock<HashMap<String, Course>>,
    enrollments: RwLock<HashMap<String, Enrollment>>,
}

impl SecurityTrainingRegister {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new course.
    pub fn register_course(&self, course: Course) -> SandboxResult<()> {
        let mut g = self
            .courses
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        if g.contains_key(&course.course_id) {
            return Err(SandboxError::Other(format!(
                "course already registered: {}",
                course.course_id
            )));
        }
        g.insert(course.course_id.clone(), course);
        Ok(())
    }

    /// Set course active flag.
    pub fn set_course_active(&self, course_id: &str, active: bool) -> SandboxResult<()> {
        let mut g = self
            .courses
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let c = g
            .get_mut(course_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown course {course_id}")))?;
        c.active = active;
        Ok(())
    }

    /// Add a tag to a course (deduplicated).
    pub fn add_course_tag(
        &self,
        course_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .courses
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let c = g
            .get_mut(course_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown course {course_id}")))?;
        let tag = tag.into();
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a course.
    pub fn get_course(&self, course_id: &str) -> Option<Course> {
        let g = self.courses.read().ok()?;
        g.get(course_id).cloned()
    }

    /// All courses.
    pub fn all_courses(&self) -> Vec<Course> {
        match self.courses.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active courses.
    pub fn active_courses(&self) -> Vec<Course> {
        self.all_courses().into_iter().filter(|c| c.active).collect()
    }

    /// Enroll a subject in a course. Errors if the course isn't
    /// registered, the course is inactive, or the enrollment id collides.
    pub fn enroll(&self, enrollment: Enrollment) -> SandboxResult<()> {
        if !matches!(enrollment.stage, EnrollmentStage::Assigned) {
            return Err(SandboxError::Other(format!(
                "enrollment must start Assigned, got {:?}",
                enrollment.stage
            )));
        }
        let course_active = {
            let cg = self
                .courses
                .read()
                .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
            let c = cg.get(&enrollment.course_id).ok_or_else(|| {
                SandboxError::Other(format!("unknown course {}", enrollment.course_id))
            })?;
            if c.tenant_id != enrollment.tenant_id {
                return Err(SandboxError::Other(format!(
                    "tenant mismatch: enrollment {} vs course {}",
                    enrollment.tenant_id, c.tenant_id
                )));
            }
            c.active
        };
        if !course_active {
            return Err(SandboxError::Other(format!(
                "course {} is inactive",
                enrollment.course_id
            )));
        }
        let mut g = self
            .enrollments
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        if g.contains_key(&enrollment.enrollment_id) {
            return Err(SandboxError::Other(format!(
                "enrollment already registered: {}",
                enrollment.enrollment_id
            )));
        }
        g.insert(enrollment.enrollment_id.clone(), enrollment);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        enrollment_id: &str,
        new_stage: EnrollmentStage,
        at: impl Into<String>,
    ) -> SandboxResult<Enrollment> {
        let mut g = self
            .enrollments
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let e = g
            .get_mut(enrollment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown enrollment {enrollment_id}")))?;
        if !legal_transition(e.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                e.stage, new_stage
            )));
        }
        let when = at.into();
        e.stage = new_stage;
        match new_stage {
            EnrollmentStage::InProgress => {
                if e.started_at.is_none() {
                    e.started_at = Some(when);
                }
            }
            EnrollmentStage::Completed
            | EnrollmentStage::Failed
            | EnrollmentStage::Exempt
            | EnrollmentStage::Withdrawn => {
                e.completed_at = Some(when);
            }
            _ => {}
        }
        Ok(e.clone())
    }

    /// Record completion details (score + certificate). Caller is
    /// expected to follow with `transition(Completed)` or
    /// `transition(Failed)`. Allowed in Assigned or InProgress.
    pub fn record_completion(
        &self,
        enrollment_id: &str,
        score_pct: Option<u8>,
        certificate_uri: Option<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        if let Some(s) = score_pct {
            if s > 100 {
                return Err(SandboxError::Other(format!(
                    "score {s} out of range (0-100)"
                )));
            }
        }
        let mut g = self
            .enrollments
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let e = g
            .get_mut(enrollment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown enrollment {enrollment_id}")))?;
        if !matches!(
            e.stage,
            EnrollmentStage::Assigned | EnrollmentStage::InProgress
        ) {
            return Err(SandboxError::Other(format!(
                "cannot record completion on {enrollment_id}: stage is {:?}",
                e.stage
            )));
        }
        e.score_pct = score_pct;
        if let Some(uri) = certificate_uri {
            e.certificate_uri = Some(uri);
        }
        if let Some(n) = note {
            e.note = Some(n);
        }
        Ok(())
    }

    /// Set deadline.
    pub fn set_due(&self, enrollment_id: &str, at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .enrollments
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let e = g
            .get_mut(enrollment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown enrollment {enrollment_id}")))?;
        e.due_at = Some(at.into());
        Ok(())
    }

    /// Add tag to enrollment.
    pub fn add_enrollment_tag(
        &self,
        enrollment_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .enrollments
            .write()
            .map_err(|_| SandboxError::Other("training register poisoned".into()))?;
        let e = g
            .get_mut(enrollment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown enrollment {enrollment_id}")))?;
        let tag = tag.into();
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Look up an enrollment.
    pub fn get_enrollment(&self, enrollment_id: &str) -> Option<Enrollment> {
        let g = self.enrollments.read().ok()?;
        g.get(enrollment_id).cloned()
    }

    /// All enrollments.
    pub fn all_enrollments(&self) -> Vec<Enrollment> {
        match self.enrollments.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Enrollments for a tenant.
    pub fn enrollments_for_tenant(&self, tenant_id: &str) -> Vec<Enrollment> {
        self.all_enrollments()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    /// Enrollments for a subject.
    pub fn enrollments_for_subject(&self, subject_id: &str) -> Vec<Enrollment> {
        self.all_enrollments()
            .into_iter()
            .filter(|e| e.subject_id == subject_id)
            .collect()
    }

    /// Enrollments for a course.
    pub fn enrollments_for_course(&self, course_id: &str) -> Vec<Enrollment> {
        self.all_enrollments()
            .into_iter()
            .filter(|e| e.course_id == course_id)
            .collect()
    }

    /// Enrollments at a stage.
    pub fn by_stage(&self, stage: EnrollmentStage) -> Vec<Enrollment> {
        self.all_enrollments()
            .into_iter()
            .filter(|e| e.stage == stage)
            .collect()
    }

    /// Open enrollments past their deadline at `now`.
    pub fn overdue(&self, now: &str) -> Vec<Enrollment> {
        self.all_enrollments()
            .into_iter()
            .filter(|e| e.is_overdue(now))
            .collect()
    }

    /// Subjects whose latest satisfying completion of `course_id` is older
    /// than the course's recurrence_days at `now`.
    pub fn due_for_renewal(
        &self,
        course_id: &str,
        now: &str,
    ) -> Vec<Enrollment> {
        let course = match self.get_course(course_id) {
            Some(c) => c,
            None => return Vec::new(),
        };
        if course.recurrence_days == 0 {
            return Vec::new();
        }
        // Group by subject; pick latest satisfying completion per subject.
        let mut latest_per_subject: HashMap<String, Enrollment> = HashMap::new();
        for e in self.enrollments_for_course(course_id) {
            if !e.stage.is_satisfying() {
                continue;
            }
            let when = e.completed_at.clone().unwrap_or_default();
            match latest_per_subject.get(&e.subject_id) {
                Some(prev) => {
                    if when > prev.completed_at.clone().unwrap_or_default() {
                        latest_per_subject.insert(e.subject_id.clone(), e);
                    }
                }
                None => {
                    latest_per_subject.insert(e.subject_id.clone(), e);
                }
            }
        }
        let mut due = Vec::new();
        for (_, e) in latest_per_subject {
            if let Some(completed) = &e.completed_at {
                if let Some(days) = age_in_days(completed, now) {
                    if days >= course.recurrence_days as i64 {
                        due.push(e);
                    }
                }
            }
        }
        due
    }

    /// Counts.
    pub fn course_count(&self) -> usize {
        self.courses.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Counts.
    pub fn enrollment_count(&self) -> usize {
        self.enrollments.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn course(id: &str, recur_days: u32) -> Course {
        Course::new(
            id,
            "tenant-a",
            format!("Course {id}"),
            CourseKind::SecurityAwareness,
            "desc",
            "training-team",
            recur_days,
            80,
        )
    }

    fn enroll(eid: &str, course_id: &str, subject: &str) -> Enrollment {
        Enrollment::new(
            eid,
            "tenant-a",
            course_id,
            subject,
            format!("Subject {subject}"),
            "2025-01-01T00:00:00Z",
        )
    }

    #[test]
    fn register_course_and_get() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        assert!(r.get_course("c1").is_some());
    }

    #[test]
    fn duplicate_course_errors() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        let err = r.register_course(course("c1", 180)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn passing_score_clamped() {
        let c = Course::new(
            "c1",
            "t",
            "name",
            CourseKind::Privacy,
            "d",
            "o",
            0,
            150,
        );
        assert_eq!(c.passing_score_pct, 100);
    }

    #[test]
    fn enroll_requires_active_course() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.set_course_active("c1", false).unwrap();
        let err = r.enroll(enroll("e1", "c1", "alice")).unwrap_err();
        assert!(format!("{err}").contains("inactive"));
    }

    #[test]
    fn enroll_unknown_course_errors() {
        let r = SecurityTrainingRegister::new();
        let err = r.enroll(enroll("e1", "missing", "alice")).unwrap_err();
        assert!(format!("{err}").contains("unknown course"));
    }

    #[test]
    fn enroll_tenant_mismatch_errors() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        let mut e = enroll("e1", "c1", "alice");
        e.tenant_id = "tenant-b".into();
        let err = r.enroll(e).unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn enroll_must_start_assigned() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        let mut e = enroll("e1", "c1", "alice");
        e.stage = EnrollmentStage::Completed;
        let err = r.enroll(e).unwrap_err();
        assert!(format!("{err}").contains("must start Assigned"));
    }

    #[test]
    fn legal_transitions() {
        use EnrollmentStage::*;
        assert!(legal_transition(Assigned, InProgress));
        assert!(legal_transition(Assigned, Exempt));
        assert!(legal_transition(Assigned, Withdrawn));
        assert!(legal_transition(InProgress, Completed));
        assert!(legal_transition(InProgress, Failed));
        assert!(legal_transition(InProgress, Withdrawn));
        assert!(legal_transition(Failed, InProgress));
        // illegal
        assert!(!legal_transition(Assigned, Completed));
        assert!(!legal_transition(Completed, Assigned));
        assert!(!legal_transition(Withdrawn, InProgress));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap();
        r.record_completion("e1", Some(95), Some("vault://cert/c1".into()), None)
            .unwrap();
        let g = r
            .transition("e1", EnrollmentStage::Completed, "2025-01-15T00:00:00Z")
            .unwrap();
        assert_eq!(g.stage, EnrollmentStage::Completed);
        assert_eq!(g.score_pct, Some(95));
        assert_eq!(g.certificate_uri.as_deref(), Some("vault://cert/c1"));
        assert!(g.stage.is_satisfying());
    }

    #[test]
    fn record_completion_score_out_of_range() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        let err = r.record_completion("e1", Some(150), None, None).unwrap_err();
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn record_completion_when_terminal_errors() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2025-01-15T00:00:00Z")
            .unwrap();
        let err = r.record_completion("e1", Some(80), None, None).unwrap_err();
        assert!(format!("{err}").contains("cannot record"));
    }

    #[test]
    fn failed_can_retry() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Failed, "2025-01-10T00:00:00Z")
            .unwrap();
        // retry
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-15T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2025-01-20T00:00:00Z")
            .unwrap();
        assert!(r
            .get_enrollment("e1")
            .unwrap()
            .stage
            .is_satisfying());
    }

    #[test]
    fn exempt_path() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::Exempt, "2025-01-15T00:00:00Z")
            .unwrap();
        let g = r.get_enrollment("e1").unwrap();
        assert_eq!(g.stage, EnrollmentStage::Exempt);
        assert!(g.stage.is_satisfying());
    }

    #[test]
    fn withdrawn_does_not_satisfy() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::Withdrawn, "2025-01-10T00:00:00Z")
            .unwrap();
        assert!(!r
            .get_enrollment("e1")
            .unwrap()
            .stage
            .is_satisfying());
    }

    #[test]
    fn set_due_overdue_query() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.set_due("e1", "2025-02-01T00:00:00Z").unwrap();
        // Before deadline → not overdue
        assert_eq!(r.overdue("2025-01-15T00:00:00Z").len(), 0);
        // After deadline → overdue
        assert_eq!(r.overdue("2025-02-15T00:00:00Z").len(), 1);
        // Complete → no longer overdue
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2025-01-15T00:00:00Z")
            .unwrap();
        assert_eq!(r.overdue("2025-02-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn add_course_tag_dedupes() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.add_course_tag("c1", "annual").unwrap();
        r.add_course_tag("c1", "annual").unwrap();
        r.add_course_tag("c1", "mandatory").unwrap();
        assert_eq!(
            r.get_course("c1").unwrap().tags,
            vec!["annual", "mandatory"]
        );
    }

    #[test]
    fn add_enrollment_tag_dedupes() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.add_enrollment_tag("e1", "regulator-required").unwrap();
        r.add_enrollment_tag("e1", "regulator-required").unwrap();
        assert_eq!(
            r.get_enrollment("e1").unwrap().tags,
            vec!["regulator-required"]
        );
    }

    #[test]
    fn unknown_course_or_enrollment_errors() {
        let r = SecurityTrainingRegister::new();
        let err = r.set_course_active("nope", false).unwrap_err();
        assert!(format!("{err}").contains("unknown course"));
        let err = r
            .transition("nope", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown enrollment"));
    }

    #[test]
    fn enrollment_filters() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.register_course(course("c2", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.enroll(enroll("e2", "c2", "alice")).unwrap();
        r.enroll(enroll("e3", "c1", "bob")).unwrap();
        let mut other = enroll("e4", "c1", "charlie");
        other.tenant_id = "tenant-b".into();
        // Need a tenant-b course for the enrollment to register.
        let mut c2 = course("c1-b", 365);
        c2.tenant_id = "tenant-b".into();
        r.register_course(c2).unwrap();
        other.course_id = "c1-b".into();
        r.enroll(other).unwrap();

        assert_eq!(r.enrollments_for_tenant("tenant-a").len(), 3);
        assert_eq!(r.enrollments_for_tenant("tenant-b").len(), 1);
        assert_eq!(r.enrollments_for_subject("alice").len(), 2);
        assert_eq!(r.enrollments_for_subject("bob").len(), 1);
        assert_eq!(r.enrollments_for_course("c1").len(), 2);
        assert_eq!(r.enrollments_for_course("c2").len(), 1);
    }

    #[test]
    fn by_stage_filter() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.enroll(enroll("e2", "c1", "bob")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2025-01-02T00:00:00Z")
            .unwrap();
        assert_eq!(r.by_stage(EnrollmentStage::Assigned).len(), 1);
        assert_eq!(r.by_stage(EnrollmentStage::InProgress).len(), 1);
    }

    #[test]
    fn due_for_renewal_basic() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2024-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2024-01-15T00:00:00Z")
            .unwrap();
        // 366 days later — due
        let due = r.due_for_renewal("c1", "2025-01-16T00:00:00Z");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].subject_id, "alice");
        // 30 days later — not due
        let due = r.due_for_renewal("c1", "2024-02-15T00:00:00Z");
        assert!(due.is_empty());
    }

    #[test]
    fn due_for_renewal_picks_latest_completion_per_subject() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 365)).unwrap();
        // Alice completed twice; the latest one is the anchor.
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2023-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2023-01-15T00:00:00Z")
            .unwrap();
        r.enroll(enroll("e2", "c1", "alice")).unwrap();
        r.transition("e2", EnrollmentStage::InProgress, "2024-01-02T00:00:00Z")
            .unwrap();
        r.transition("e2", EnrollmentStage::Completed, "2024-12-15T00:00:00Z")
            .unwrap();
        // Asking on 2025-06-01 — the older one is past 365d but the newer
        // is only 167d old → not yet due.
        let due = r.due_for_renewal("c1", "2025-06-01T00:00:00Z");
        assert!(due.is_empty());
    }

    #[test]
    fn due_for_renewal_unknown_course_empty() {
        let r = SecurityTrainingRegister::new();
        assert!(r.due_for_renewal("nope", "2025-01-01T00:00:00Z").is_empty());
    }

    #[test]
    fn due_for_renewal_zero_recurrence_empty() {
        let r = SecurityTrainingRegister::new();
        r.register_course(course("c1", 0)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        r.transition("e1", EnrollmentStage::InProgress, "2024-01-02T00:00:00Z")
            .unwrap();
        r.transition("e1", EnrollmentStage::Completed, "2024-01-15T00:00:00Z")
            .unwrap();
        assert!(r
            .due_for_renewal("c1", "2030-01-01T00:00:00Z")
            .is_empty());
    }

    #[test]
    fn stage_helpers() {
        for s in [
            EnrollmentStage::Completed,
            EnrollmentStage::Failed,
            EnrollmentStage::Exempt,
            EnrollmentStage::Withdrawn,
        ] {
            assert!(s.is_terminal());
        }
        for s in [EnrollmentStage::Assigned, EnrollmentStage::InProgress] {
            assert!(!s.is_terminal());
        }
        assert!(EnrollmentStage::Completed.is_satisfying());
        assert!(EnrollmentStage::Exempt.is_satisfying());
        assert!(!EnrollmentStage::Failed.is_satisfying());
        assert!(!EnrollmentStage::Withdrawn.is_satisfying());
    }

    #[test]
    fn counts() {
        let r = SecurityTrainingRegister::new();
        assert_eq!(r.course_count(), 0);
        assert_eq!(r.enrollment_count(), 0);
        r.register_course(course("c1", 365)).unwrap();
        r.enroll(enroll("e1", "c1", "alice")).unwrap();
        assert_eq!(r.course_count(), 1);
        assert_eq!(r.enrollment_count(), 1);
    }

    #[test]
    fn course_serde() {
        let c = course("c1", 365);
        let j = serde_json::to_string(&c).unwrap();
        let back: Course = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enrollment_serde() {
        let e = enroll("e1", "c1", "alice");
        let j = serde_json::to_string(&e).unwrap();
        let back: Enrollment = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            CourseKind::SecurityAwareness,
            CourseKind::Privacy,
            CourseKind::Hipaa,
            CourseKind::Pci,
            CourseKind::AntiBribery,
            CourseKind::Aml,
            CourseKind::CodeOfConduct,
            CourseKind::InsiderThreat,
            CourseKind::AiResponsibility,
            CourseKind::RoleSpecific,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<CourseKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            EnrollmentStage::Assigned,
            EnrollmentStage::InProgress,
            EnrollmentStage::Completed,
            EnrollmentStage::Failed,
            EnrollmentStage::Exempt,
            EnrollmentStage::Withdrawn,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<EnrollmentStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}

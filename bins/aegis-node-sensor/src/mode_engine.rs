//! Phase 3.6 (Agent Cage): the observe/enforce/lockdown decision policy
//! (`docs/AegisAgent_Runtime_Data_Plane.md`, section 5 — Sensor modes).
//!
//! This is deliberately narrow: it defines what a given mode + gateway
//! reachability combination *implies* for a controlled action or an
//! unaccounted-for run. Signed control commands are applied by
//! [`crate::process_enforcer::ProcessEnforcer`] (host PIDs) and the cage
//! runner (Docker sandboxes). This module stays the decision *matrix* for
//! local gateway-down / mode posture — not the signal applicator.

use crate::config::SensorMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayReachability {
    Reachable,
    Unreachable,
}

/// What the sensor should do with a controlled action (tool call, egress
/// attempt, credential issuance, new sandbox start, ...) under the current
/// mode + reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDecision {
    /// Allow. In `observe` this is unconditional (visibility, not
    /// gatekeeping) — the action still generates events that ship/buffer
    /// normally regardless. In `enforce` this only applies when the gateway
    /// can weigh in.
    Allow,
    /// Refuse the action locally. The gateway isn't reachable to make a
    /// real decision (`enforce`), or this mode never trusts a raw
    /// controlled action regardless (`lockdown`).
    Block,
}

/// What the sensor should do about a run it cannot account for (unknown
/// agent identity, no matching `agent_run` record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownRunDecision {
    /// Leave it running — no local emergency policy triggers containment.
    Continue,
    /// Autonomously pause or kill it. The sensor cannot ask the gateway,
    /// and this mode's posture is "contain first, explain later."
    PauseOrKill,
}

/// Holds the sensor's current mode and answers "what do I do" questions
/// against it. Mode is fixed at construction (from config/registration) —
/// runtime mode transitions via signed command are future work once the
/// Control Command Protocol's action vocabulary grows beyond `kill_run`.
pub struct ModeEngine {
    mode: SensorMode,
}

impl ModeEngine {
    pub fn new(mode: SensorMode) -> Self {
        Self { mode }
    }

    pub fn mode(&self) -> SensorMode {
        self.mode
    }

    /// Decide a controlled action.
    ///
    /// | mode     | reachable   | unreachable |
    /// |----------|-------------|-------------|
    /// | observe  | Allow       | Allow       |
    /// | enforce  | Allow       | Block       |
    /// | lockdown | Block       | Block       |
    pub fn decide_controlled_action(&self, gateway: GatewayReachability) -> ActionDecision {
        match (self.mode, gateway) {
            (SensorMode::Observe, _) => ActionDecision::Allow,
            (SensorMode::Enforce, GatewayReachability::Reachable) => ActionDecision::Allow,
            (SensorMode::Enforce, GatewayReachability::Unreachable) => ActionDecision::Block,
            (SensorMode::Lockdown, _) => ActionDecision::Block,
        }
    }

    /// Decide what to do about a run with no accounted-for identity. Only
    /// `lockdown` while disconnected autonomously contains — every other
    /// combination defers, either because there's a gateway to ask or
    /// because the mode's posture is visibility/supervised-risk rather than
    /// containment.
    pub fn decide_unknown_run(&self, gateway: GatewayReachability) -> UnknownRunDecision {
        match (self.mode, gateway) {
            (SensorMode::Lockdown, GatewayReachability::Unreachable) => {
                UnknownRunDecision::PauseOrKill
            }
            _ => UnknownRunDecision::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_mode_always_allows_and_buffers_regardless_of_reachability() {
        let engine = ModeEngine::new(SensorMode::Observe);
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Reachable),
            ActionDecision::Allow
        );
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Unreachable),
            ActionDecision::Allow
        );
    }

    #[test]
    fn observe_mode_never_autonomously_contains_unknown_runs() {
        let engine = ModeEngine::new(SensorMode::Observe);
        assert_eq!(
            engine.decide_unknown_run(GatewayReachability::Unreachable),
            UnknownRunDecision::Continue
        );
    }

    #[test]
    fn enforce_mode_allows_controlled_action_when_gateway_reachable() {
        let engine = ModeEngine::new(SensorMode::Enforce);
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Reachable),
            ActionDecision::Allow
        );
    }

    #[test]
    fn enforce_mode_blocks_controlled_action_when_gateway_unreachable() {
        let engine = ModeEngine::new(SensorMode::Enforce);
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Unreachable),
            ActionDecision::Block
        );
    }

    #[test]
    fn enforce_mode_does_not_autonomously_contain_unknown_runs() {
        // Enforce blocks *new* controlled actions when disconnected, but
        // doesn't unilaterally kill runs already in flight — that's
        // lockdown's posture.
        let engine = ModeEngine::new(SensorMode::Enforce);
        assert_eq!(
            engine.decide_unknown_run(GatewayReachability::Unreachable),
            UnknownRunDecision::Continue
        );
    }

    #[test]
    fn lockdown_mode_blocks_controlled_actions_regardless_of_reachability() {
        let engine = ModeEngine::new(SensorMode::Lockdown);
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Reachable),
            ActionDecision::Block
        );
        assert_eq!(
            engine.decide_controlled_action(GatewayReachability::Unreachable),
            ActionDecision::Block
        );
    }

    #[test]
    fn lockdown_mode_pauses_or_kills_mock_unknown_run_when_gateway_unreachable() {
        let engine = ModeEngine::new(SensorMode::Lockdown);
        assert_eq!(
            engine.decide_unknown_run(GatewayReachability::Unreachable),
            UnknownRunDecision::PauseOrKill
        );
    }

    #[test]
    fn lockdown_mode_defers_unknown_run_containment_when_gateway_reachable() {
        // The gateway can be asked to make the real call while it's up —
        // autonomous containment is reserved for being cut off.
        let engine = ModeEngine::new(SensorMode::Lockdown);
        assert_eq!(
            engine.decide_unknown_run(GatewayReachability::Reachable),
            UnknownRunDecision::Continue
        );
    }

    #[test]
    fn mode_accessor_reports_the_constructed_mode() {
        assert_eq!(
            ModeEngine::new(SensorMode::Enforce).mode(),
            SensorMode::Enforce
        );
    }
}

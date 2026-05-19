use std::time::Instant;

use crate::math::{
    DIM, add, barrier_condition_proxy, barrier_gradient, barrier_value, dot, is_feasible,
    kkt_residual, norm, objective, parallel_gradient_check, scale, slacks, sub,
};

const MEMORY: usize = 9;

#[derive(Clone)]
pub struct Optimizer {
    pub x: [f64; DIM],
    pub mu: f64,
    pub iter: usize,
    pub total_steps: usize,
    history: Vec<LbfgsPair>,
    pub last_gradient_error: f64,
    pub last_verifier: VerifierReport,
    pub accepted: usize,
    pub rejected: usize,
    pub start: Instant,
}

impl Optimizer {
    pub fn new(total_steps: usize) -> Self {
        let mut optimizer = Self {
            x: [-1.05, 1.10, -0.74, 0.94, -0.46, 0.55, -0.18, 0.24],
            mu: 8.0e-2,
            iter: 0,
            total_steps,
            history: Vec::with_capacity(MEMORY),
            last_gradient_error: 0.0,
            last_verifier: VerifierReport::default(),
            accepted: 0,
            rejected: 0,
            start: Instant::now(),
        };

        if !is_feasible(&optimizer.x) {
            optimizer.x = [0.0; DIM];
        }
        optimizer
    }

    pub fn step(&mut self) -> Frame {
        if self.iter > 0 && self.iter.is_multiple_of(42) {
            self.mu = (self.mu * 0.72).max(1.0e-6);
            self.history.clear();
        }

        let before = Metrics::at(self.x, self.mu);
        if before.grad_norm < 1.0e-6 {
            self.last_verifier = verify(self.x, self.mu, before, before, self.last_gradient_error);
            self.iter += 1;
            return Frame {
                before,
                after: before,
                alpha: 0.0,
                backtracks: 0,
                accepted: true,
                converged: true,
            };
        }

        let grad = barrier_gradient(&self.x, self.mu);
        let mut direction = self.search_direction(&grad);

        let descent = dot(&grad, &direction);
        if !descent.is_finite() || descent >= -1.0e-12 {
            direction = scale(&grad, -1.0);
            self.history.clear();
        }

        let step_result = line_search(self.x, direction, grad, self.mu);
        let mut accepted = false;

        if let Some((next_x, alpha, backtracks, after)) = step_result.accepted {
            let next_grad = barrier_gradient(&next_x, self.mu);
            let s = sub(&next_x, &self.x);
            let y = sub(&next_grad, &grad);
            self.push_lbfgs(s, y);
            self.x = next_x;
            self.accepted += 1;
            accepted = true;

            if self.iter.is_multiple_of(9) {
                self.last_gradient_error = parallel_gradient_check(self.x, self.mu);
            }
            self.last_verifier = verify(self.x, self.mu, before, after, self.last_gradient_error);

            self.iter += 1;
            Frame {
                before,
                after,
                alpha,
                backtracks,
                accepted,
                converged: false,
            }
        } else {
            self.rejected += 1;
            self.history.clear();
            self.last_verifier = verify(self.x, self.mu, before, before, self.last_gradient_error);

            self.iter += 1;
            Frame {
                before,
                after: before,
                alpha: 0.0,
                backtracks: 32,
                accepted,
                converged: false,
            }
        }
    }

    pub fn run_without_dashboard(&mut self) {
        for _ in 0..self.total_steps {
            self.step();
        }
    }

    fn search_direction(&self, grad: &[f64; DIM]) -> [f64; DIM] {
        if self.history.is_empty() {
            return scale(grad, -1.0 / norm(grad).max(1.0));
        }

        let mut q = *grad;
        let mut alphas = Vec::with_capacity(self.history.len());

        for pair in self.history.iter().rev() {
            let alpha = pair.rho * dot(&pair.s, &q);
            q = sub(&q, &scale(&pair.y, alpha));
            alphas.push(alpha);
        }

        let last = self.history.last().unwrap();
        let yy = dot(&last.y, &last.y).max(1.0e-12);
        let gamma = (dot(&last.s, &last.y) / yy).clamp(1.0e-4, 1.0e2);
        let mut r = scale(&q, gamma);

        for (pair, alpha) in self.history.iter().zip(alphas.iter().rev()) {
            let beta = pair.rho * dot(&pair.y, &r);
            r = add(&r, &scale(&pair.s, alpha - beta));
        }

        let direction = scale(&r, -1.0);
        let direction_norm = norm(&direction);
        if direction_norm > 12.0 {
            scale(&direction, 12.0 / direction_norm)
        } else {
            direction
        }
    }

    fn push_lbfgs(&mut self, s: [f64; DIM], y: [f64; DIM]) {
        let sy = dot(&s, &y);
        if sy <= 1.0e-10 || !sy.is_finite() {
            return;
        }
        if self.history.len() == MEMORY {
            self.history.remove(0);
        }
        self.history.push(LbfgsPair {
            s,
            y,
            rho: 1.0 / sy,
        });
    }
}

#[derive(Clone, Copy)]
struct LbfgsPair {
    s: [f64; DIM],
    y: [f64; DIM],
    rho: f64,
}

#[derive(Clone, Copy)]
pub struct Frame {
    pub before: Metrics,
    pub after: Metrics,
    pub alpha: f64,
    pub backtracks: usize,
    pub accepted: bool,
    pub converged: bool,
}

#[derive(Clone, Copy)]
pub struct Metrics {
    pub raw: f64,
    pub barrier: f64,
    pub phi: f64,
    pub grad_norm: f64,
    pub kkt: f64,
    pub min_slack: f64,
    pub condition_proxy: f64,
}

impl Metrics {
    pub fn at(x: [f64; DIM], mu: f64) -> Self {
        let raw = objective(&x);
        let current_slacks = slacks(&x);
        let barrier = -mu * current_slacks.iter().map(|s| s.ln()).sum::<f64>();
        let phi = raw + barrier;
        let grad = barrier_gradient(&x, mu);
        let grad_norm = norm(&grad);
        let kkt = kkt_residual(&x, mu);
        let min_slack = current_slacks.iter().copied().fold(f64::INFINITY, f64::min);
        let condition_proxy = barrier_condition_proxy(&x, mu);

        Self {
            raw,
            barrier,
            phi,
            grad_norm,
            kkt,
            min_slack,
            condition_proxy,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct VerifierReport {
    pub finite: bool,
    pub feasible: bool,
    pub armijo: bool,
    pub gradient: bool,
    pub kkt: bool,
    pub barrier: bool,
}

impl VerifierReport {
    pub fn pass_count(self) -> usize {
        [
            self.finite,
            self.feasible,
            self.armijo,
            self.gradient,
            self.kkt,
            self.barrier,
        ]
        .iter()
        .filter(|passed| **passed)
        .count()
    }
}

fn line_search(
    x: [f64; DIM],
    direction: [f64; DIM],
    grad: [f64; DIM],
    mu: f64,
) -> LineSearchResult {
    let phi0 = barrier_value(&x, mu);
    let slope = dot(&grad, &direction);
    let c1 = 1.0e-4;
    let mut alpha = 1.0;

    for backtracks in 0..32 {
        let trial = add(&x, &scale(&direction, alpha));
        if is_feasible(&trial) {
            let phi_trial = barrier_value(&trial, mu);
            if phi_trial.is_finite() && phi_trial <= phi0 + c1 * alpha * slope {
                return LineSearchResult {
                    accepted: Some((trial, alpha, backtracks, Metrics::at(trial, mu))),
                };
            }
        }
        alpha *= 0.5;
    }

    LineSearchResult { accepted: None }
}

struct LineSearchResult {
    accepted: Option<([f64; DIM], f64, usize, Metrics)>,
}

fn verify(
    x: [f64; DIM],
    mu: f64,
    before: Metrics,
    after: Metrics,
    gradient_error: f64,
) -> VerifierReport {
    let current_slacks = slacks(&x);
    VerifierReport {
        finite: x.iter().all(|v| v.is_finite()) && after.phi.is_finite(),
        feasible: current_slacks.iter().all(|s| *s > 1.0e-10),
        armijo: after.phi <= before.phi + 1.0e-7,
        gradient: gradient_error <= 4.0e-4,
        kkt: after.kkt.is_finite() && after.kkt < 2.5e4,
        barrier: mu > 0.0 && after.min_slack > 1.0e-8,
    }
}

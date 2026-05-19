use std::f64::consts::PI;
use std::thread;

pub const DIM: usize = 8;
pub const BOX: f64 = 1.70;
pub const RADIUS2: f64 = 10.80;
pub const COUPLE_HI: f64 = 2.45;
pub const COUPLE_LO: f64 = -2.35;
pub const EPS: f64 = 1.0e-6;

pub const WEIGHTS: [f64; DIM] = [0.92, 0.71, 1.17, 0.54, 1.08, 0.83, 0.66, 1.25];
pub const ALT_WEIGHTS: [f64; DIM] = [1.11, -0.77, 0.64, -1.04, 0.82, -0.58, 0.93, -0.49];
pub const TARGET: [f64; DIM] = [0.88, 0.80, 0.67, 0.47, 0.33, 0.18, 0.08, -0.02];

pub fn objective(x: &[f64; DIM]) -> f64 {
    let mut value = 0.0;

    for i in 0..DIM - 1 {
        let valley = x[i + 1] - x[i] * x[i];
        let anchor = 1.0 - x[i];
        value += 100.0 * valley * valley + anchor * anchor;
    }

    for i in 0..DIM {
        let d = x[i] - TARGET[i];
        let freq = 1.7 + 0.19 * i as f64;
        value += 0.045 * d.powi(4) + 0.018 * (freq * x[i] + 0.31 * i as f64).sin().powi(2);
    }

    value
}

pub fn objective_gradient(x: &[f64; DIM]) -> [f64; DIM] {
    let mut grad = [0.0; DIM];

    for i in 0..DIM - 1 {
        let valley = x[i + 1] - x[i] * x[i];
        let anchor = 1.0 - x[i];
        grad[i] += -400.0 * x[i] * valley - 2.0 * anchor;
        grad[i + 1] += 200.0 * valley;
    }

    for i in 0..DIM {
        let d = x[i] - TARGET[i];
        let freq = 1.7 + 0.19 * i as f64;
        grad[i] += 0.18 * d.powi(3);
        grad[i] += 0.018 * freq * (2.0 * (freq * x[i] + 0.31 * i as f64)).sin();
    }

    grad
}

pub fn barrier_value(x: &[f64; DIM], mu: f64) -> f64 {
    if !is_feasible(x) {
        return f64::INFINITY;
    }
    objective(x) - mu * slacks(x).iter().map(|s| s.ln()).sum::<f64>()
}

pub fn barrier_gradient(x: &[f64; DIM], mu: f64) -> [f64; DIM] {
    let mut grad = objective_gradient(x);
    let slack = slacks(x);

    for i in 0..DIM {
        grad[i] += mu / slack[i];
        grad[i] -= mu / slack[DIM + i];
        grad[i] += 2.0 * mu * x[i] / slack[2 * DIM];
        grad[i] += mu * WEIGHTS[i] / slack[2 * DIM + 1];
        grad[i] -= mu * ALT_WEIGHTS[i] / slack[2 * DIM + 2];
    }

    grad
}

pub fn slacks(x: &[f64; DIM]) -> Vec<f64> {
    let mut values = Vec::with_capacity(2 * DIM + 3);
    for value in x {
        values.push(BOX - *value);
    }
    for value in x {
        values.push(*value + BOX);
    }
    values.push(RADIUS2 - dot(x, x));
    values.push(COUPLE_HI - weighted_sum(WEIGHTS, x));
    values.push(weighted_sum(ALT_WEIGHTS, x) - COUPLE_LO);
    values
}

pub fn is_feasible(x: &[f64; DIM]) -> bool {
    slacks(x).into_iter().all(|s| s.is_finite() && s > 1.0e-10)
}

pub fn kkt_residual(x: &[f64; DIM], mu: f64) -> f64 {
    norm(&barrier_gradient(x, mu))
}

pub fn barrier_condition_proxy(x: &[f64; DIM], mu: f64) -> f64 {
    let slack = slacks(x);
    let mut curvature = 0.0;
    for i in 0..DIM {
        curvature += mu / slack[i].powi(2);
        curvature += mu / slack[DIM + i].powi(2);
    }
    curvature += 4.0 * mu * dot(x, x) / slack[2 * DIM].powi(2);
    curvature += mu * dot(&WEIGHTS, &WEIGHTS) / slack[2 * DIM + 1].powi(2);
    curvature += mu * dot(&ALT_WEIGHTS, &ALT_WEIGHTS) / slack[2 * DIM + 2].powi(2);
    curvature.max(1.0)
}

pub fn parallel_gradient_check(x: [f64; DIM], mu: f64) -> f64 {
    let threads = available_threads().clamp(1, 16);
    let analytic = barrier_gradient(&x, mu);
    let mut handles = Vec::with_capacity(threads);

    for worker in 0..threads {
        handles.push(thread::spawn(move || {
            let direction = deterministic_direction(worker);
            let projected = dot(&analytic, &direction);
            let mut eps = EPS;
            let mut numerical = f64::NAN;

            for _ in 0..8 {
                let plus = add(&x, &scale(&direction, eps));
                let minus = add(&x, &scale(&direction, -eps));
                if is_feasible(&plus) && is_feasible(&minus) {
                    numerical =
                        (barrier_value(&plus, mu) - barrier_value(&minus, mu)) / (2.0 * eps);
                    break;
                }
                eps *= 0.25;
            }

            if numerical.is_finite() {
                (numerical - projected).abs() / (1.0 + numerical.abs() + projected.abs())
            } else {
                1.0
            }
        }));
    }

    handles
        .into_iter()
        .map(|handle| handle.join().unwrap_or(1.0))
        .fold(0.0, f64::max)
}

pub fn available_threads() -> usize {
    thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
}

pub fn add(a: &[f64; DIM], b: &[f64; DIM]) -> [f64; DIM] {
    let mut out = [0.0; DIM];
    for i in 0..DIM {
        out[i] = a[i] + b[i];
    }
    out
}

pub fn sub(a: &[f64; DIM], b: &[f64; DIM]) -> [f64; DIM] {
    let mut out = [0.0; DIM];
    for i in 0..DIM {
        out[i] = a[i] - b[i];
    }
    out
}

pub fn scale(a: &[f64; DIM], factor: f64) -> [f64; DIM] {
    let mut out = [0.0; DIM];
    for i in 0..DIM {
        out[i] = a[i] * factor;
    }
    out
}

pub fn dot(a: &[f64; DIM], b: &[f64; DIM]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

pub fn norm(a: &[f64; DIM]) -> f64 {
    dot(a, a).sqrt()
}

fn weighted_sum(weights: [f64; DIM], x: &[f64; DIM]) -> f64 {
    weights.iter().zip(x.iter()).map(|(w, v)| w * v).sum()
}

fn deterministic_direction(seed: usize) -> [f64; DIM] {
    let mut direction = [0.0; DIM];
    for (i, value) in direction.iter_mut().enumerate() {
        let angle = (seed as f64 + 1.0) * (i as f64 + 1.0) * PI / 7.0;
        *value = angle.sin() + 0.37 * (angle * 1.618).cos();
    }
    let length = norm(&direction).max(1.0e-12);
    scale(&direction, 1.0 / length)
}

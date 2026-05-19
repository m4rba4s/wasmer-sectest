use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Cranelift,
    Singlepass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    InProcess,
    Process,
}

impl IsolationMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" | "in-process" | "inprocess" => Some(Self::InProcess),
            "process" | "supervisor" => Some(Self::Process),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::InProcess => "in-process",
            Self::Process => "process",
        }
    }
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cranelift => "cranelift",
            Self::Singlepass => "singlepass",
        }
    }
}

fn require_value(args: &[String], index: usize, flag: &str) -> String {
    let Some(value) = args.get(index + 1) else {
        eprintln!("{flag} requires a value");
        std::process::exit(2);
    };
    if value.starts_with("--") {
        eprintln!("{flag} requires a value");
        std::process::exit(2);
    }
    value.clone()
}

fn parse_positive_usize(value: &str, flag: &str) -> usize {
    match value.parse::<usize>() {
        Ok(parsed) if parsed > 0 => parsed,
        _ => {
            eprintln!("{flag} requires a positive integer");
            std::process::exit(2);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    All,
    Interview,
    Abi,
    Capability,
    Resource,
    Memory,
}

impl Profile {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "all" => Some(Self::All),
            "interview" => Some(Self::Interview),
            "abi" => Some(Self::Abi),
            "capability" | "capabilities" | "caps" => Some(Self::Capability),
            "resource" | "resources" | "dos" => Some(Self::Resource),
            "memory" => Some(Self::Memory),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Interview => "interview",
            Self::Abi => "abi",
            Self::Capability => "capability",
            Self::Resource => "resource",
            Self::Memory => "memory",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Markdown,
    Sarif,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub case: Option<String>,
    pub corpus_dir: Option<String>,
    pub emit_wasm_dir: Option<String>,
    pub interview: bool,
    pub list: bool,
    pub menu: bool,
    pub no_color: bool,
    pub output_format: OutputFormat,
    pub policy_path: Option<String>,
    pub allow_unmetered: bool,
    pub isolation: IsolationMode,
    pub profile: Profile,
    pub report_path: Option<String>,
    pub summary_only: bool,
    pub timeout_ms: Option<u64>,
    pub tui: bool,
    pub tui_delay_ms: u64,
    pub repeat: usize,
    pub backend: Backend,
    pub worker_case: Option<String>,
    pub worker_execute_static: bool,
}

impl Config {
    pub fn from_args() -> Self {
        let mut case = None;
        let mut corpus_dir = None;
        let mut emit_wasm_dir = None;
        let mut interview = false;
        let mut list = false;
        let mut menu = false;
        let mut no_color = false;
        let mut output_format = OutputFormat::Text;
        let mut policy_path = None;
        let mut allow_unmetered = false;
        let mut isolation = IsolationMode::InProcess;
        let mut profile = Profile::All;
        let mut report_path = None;
        let mut summary_only = false;
        let mut timeout_ms = None;
        let mut tui = false;
        let mut tui_delay_ms = 120u64;
        let mut repeat = 1usize;
        let mut backend = Backend::Cranelift;
        let mut worker_case = None;
        let mut worker_execute_static = false;

        let args: Vec<String> = env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--case" | "--scenario" => {
                    case = Some(require_value(&args, i, args[i].as_str()));
                    i += 1;
                }
                "--profile" => {
                    let value = require_value(&args, i, "--profile");
                    profile = match Profile::parse(&value) {
                        Some(profile) => profile,
                        None => {
                            eprintln!(
                                "Unsupported profile '{value}'. Use all, interview, abi, capability, resource, memory."
                            );
                            std::process::exit(2);
                        }
                    };
                    if profile == Profile::Interview {
                        interview = true;
                    }
                    i += 1;
                }
                "--emit-wasm-dir" => {
                    emit_wasm_dir = Some(require_value(&args, i, "--emit-wasm-dir"));
                    i += 1;
                }
                "--corpus" => {
                    corpus_dir = Some(require_value(&args, i, "--corpus"));
                    i += 1;
                }
                "--format" => {
                    let value = require_value(&args, i, "--format");
                    output_format = match OutputFormat::parse(&value) {
                        Some(format) => format,
                        None => {
                            eprintln!(
                                "Unsupported format '{value}'. Use text, json, markdown, sarif."
                            );
                            std::process::exit(2);
                        }
                    };
                    if output_format != OutputFormat::Text {
                        no_color = true;
                    }
                    i += 1;
                }
                "--report" => {
                    report_path = Some(require_value(&args, i, "--report"));
                    i += 1;
                }
                "--policy" => {
                    policy_path = Some(require_value(&args, i, "--policy"));
                    i += 1;
                }
                "--allow-unmetered" => allow_unmetered = true,
                "--isolate" => {
                    let value = require_value(&args, i, "--isolate");
                    isolation = match IsolationMode::parse(&value) {
                        Some(mode) => mode,
                        None => {
                            eprintln!("Unsupported isolation mode '{value}'. Use none or process.");
                            std::process::exit(2);
                        }
                    };
                    i += 1;
                }
                "--timeout-ms" => {
                    let value = require_value(&args, i, "--timeout-ms");
                    timeout_ms = Some(parse_positive_u64(&value, "--timeout-ms"));
                    i += 1;
                }
                "--backend" => {
                    let value = require_value(&args, i, "--backend");
                    backend = match value.as_str() {
                        "cranelift" => Backend::Cranelift,
                        "singlepass" => Backend::Singlepass,
                        other => {
                            eprintln!(
                                "Unsupported backend '{other}'. Use cranelift or singlepass."
                            );
                            std::process::exit(2);
                        }
                    };
                    i += 1;
                }
                "--repeat" => {
                    let value = require_value(&args, i, "--repeat");
                    repeat = parse_positive_usize(&value, "--repeat");
                    i += 1;
                }
                "--tui" | "--live" => tui = true,
                "--tui-delay-ms" => {
                    let value = require_value(&args, i, "--tui-delay-ms");
                    tui_delay_ms = match value.parse::<u64>() {
                        Ok(delay) if delay <= 2000 => delay,
                        _ => {
                            eprintln!("--tui-delay-ms requires an integer from 0 to 2000");
                            std::process::exit(2);
                        }
                    };
                    i += 1;
                }
                "--stress" => {
                    let value = require_value(&args, i, "--stress");
                    repeat = parse_positive_usize(&value, "--stress");
                    summary_only = true;
                    i += 1;
                }
                "--list" => list = true,
                "--all" => {
                    case = None;
                    profile = Profile::All;
                }
                "--interview" => {
                    interview = true;
                    profile = Profile::Interview;
                }
                "--menu" => menu = true,
                "--no-color" => no_color = true,
                "--summary-only" => summary_only = true,
                "--worker-case" => {
                    worker_case = Some(require_value(&args, i, "--worker-case"));
                    i += 1;
                }
                "--worker-execute-static-audit" => worker_execute_static = true,
                "--help" | "-h" => {
                    println!("Usage: wasmer-demo [--case NAME] [--profile NAME] [--format F]");
                    println!("  --all               run the full corpus sequentially (default)");
                    println!("  --list              list hostile guest cases");
                    println!("  --case NAME         run one case instead of the selected profile");
                    println!("  --scenario NAME     alias for --case");
                    println!("  --corpus DIR        load external .wat/.wasm corpus directory");
                    println!(
                        "  --menu              interactive security console with session history"
                    );
                    println!("  --tui               live terminal security cockpit");
                    println!("  --live              alias for --tui");
                    println!("  --tui-delay-ms N    frame delay for --tui, default 120");
                    println!("  --interview         curated attack -> gate -> result flow");
                    println!(
                        "  --profile NAME      all, interview, abi, capability, resource, memory"
                    );
                    println!("  --emit-wasm-dir D   compile WAT guests to D/*.wasm and exit");
                    println!("  --repeat N          repeat selected cases, default 1");
                    println!(
                        "  --stress N          repeat selected cases N times with summary output"
                    );
                    println!("  --format F          text, json, markdown, sarif");
                    println!("  --report PATH       write selected report format to a file");
                    println!(
                        "  --policy PATH       load policy limits and capabilities from TOML-like file"
                    );
                    println!(
                        "  --allow-unmetered   allow modules without the host.tick CPU budget import"
                    );
                    println!(
                        "  --isolate MODE      none or process; process runs cases under a supervisor"
                    );
                    println!("  --timeout-ms N      process supervisor timeout, default 250");
                    println!("  --backend NAME      cranelift or singlepass");
                    println!("  --no-color          disable ANSI colors");
                    println!(
                        "  --summary-only      print aggregate results and failing cases only"
                    );
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument '{other}'");
                    eprintln!("use --help for usage");
                    std::process::exit(2);
                }
            }
            i += 1;
        }

        Self {
            case,
            corpus_dir,
            emit_wasm_dir,
            interview,
            list,
            menu,
            no_color,
            output_format,
            policy_path,
            allow_unmetered,
            isolation,
            profile,
            report_path,
            summary_only,
            timeout_ms,
            tui,
            tui_delay_ms,
            repeat,
            backend,
            worker_case,
            worker_execute_static,
        }
    }
}

fn parse_positive_u64(value: &str, flag: &str) -> u64 {
    match value.parse::<u64>() {
        Ok(parsed) if parsed > 0 => parsed,
        _ => {
            eprintln!("{flag} requires a positive integer");
            std::process::exit(2);
        }
    }
}

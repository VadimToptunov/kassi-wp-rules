# Kassi WP Rules

Security rules for WordPress plugin and theme code. Each rule describes a vulnerability class:
where tainted data comes from (sources), what neutralizes it (sanitizers) and where it becomes
dangerous (sinks). The rules are consumed by
[Kassi Security Inspections for WordPress](https://github.com/VadimToptunov/kassi-wp-security-linter),
a PhpStorm plugin.

Every rule maps to a CWE and cites at least one real, fixed CVE as an example of its class.

## Format

One YAML file per rule under `rules/<platform>/`.

```yaml
id: WP-004
platform: wordpress          # mandatory
cwe: 862
severity: high               # low | medium | high | critical
summary: REST route without permission_callback
source: [register_rest_route]
sanitizers: []
sink: permission_callback_missing
precision_notes: >
  When the rule stays silent, and why.
params:                      # optional, rule-specific detection data (e.g. HTTP method tables)
  read_only_methods: [GET, HEAD]
references:
  - cve: CVE-YYYY-NNNNN
    fix_commit: https://...
    corpus: WP-004/case-01

# Consumer overlay: read only by the PhpStorm plugin.
plugin:
  description_html: inspectionDescriptions/WP004.html
  quick_fix: add_permission_callback   # or none
```

The top-level fields form the core that every consumer reads. A consumer reads its own overlay
section and ignores the rest; the validator checks the core and `plugin:` and leaves other
top-level sections alone.

## License

The rules are licensed under [CC BY 4.0](LICENSE). Reuse them freely and credit
"Kassi WP Rules (Vadim Toptunov)" with a link to this repository.

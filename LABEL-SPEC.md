# Container Label Convention (label-spec v1alpha1)

> Status: draft / v1alpha1. A generic convention for label-driven Docker /
> Compose controllers that read their desired state from container labels.

## Scope

Labels carry a tool's spec next to the service, in the Compose file. This document
defines one grammar for those labels so the shape is learned once and tooling can
parse it uniformly. It is opt-in and implies no dependency between adopting tools.

## Grammar

```
key      ::= <prefix> "." ( <meta> | <resource> )
meta     ::= "enable" | "instance"
resource ::= <kind> [ "." <name> ]      # document form — value is an embedded YAML doc
           | <kind> "." <field>         # field form   — value is a scalar
```

- Separator is `.` throughout; `/` is not used (matches the Docker label charset
  `[a-z0-9.-]`).
- A `<kind>` is either document-form or field-form, never both; whether a segment
  after `<kind>` is a name or a field is fixed by the tool's schema for that kind.

## Prefix

- Default = the tool's name, lower-case `[a-z0-9-]`.
- Configurable via `<TOOL>_LABEL_PREFIX`.
- Reverse-DNS (`com.example.tool`) is allowed but not the default.
- Never use reserved namespaces: `com.docker.*`, `io.docker.*`,
  `org.dockerproject.*`, `org.opencontainers.*`, `org.label-schema.*`.

## Values

| Case | Rule |
|---|---|
| Small fixed schema | field form, one label per field, scalar value |
| Open / nested spec | document form, one label, value = embedded YAML |
| Boolean | string `"true"` / `"false"` |
| Simple list | comma-separated |
| Complex list | YAML list inside the document |

Do not explode a nested spec into many dotted field labels; use one document-form
label.

## Named resources

- Singleton: `<prefix>.<kind>` — name defaults to the Compose service name.
- Multiple: `<prefix>.<kind>.<name>` — independent objects on one container.

## Spec vs. selector

- Spec: `<prefix>.<kind>...` — carries a document or fields.
- Selector: `<prefix>.allow.<class>: "true"` — no spec body; referenced by a
  global config file.

## Common keys

- `<prefix>.enable: "true" | "false"` — standard toggle, paired with a
  `<TOOL>_WATCH_BY_DEFAULT` switch: watch-by-default on → `enable: "false"` opts
  out; off → only `enable: "true"` opts in.
- `<prefix>.instance: "<id>"` — owning controller instance for multi-instance
  setups.

## Deprecation policy

A released tool changing labels to adopt this spec must not hard-cut:

1. Read old and new key; new wins when both are set.
2. On a deprecated key: `WARN` + increment
   `<prefix>_deprecated_label_total{label="<old-key>"}`.
3. Note it under a Deprecations heading in the changelog.
4. Remove the alias no earlier than the next minor (pre-1.0) / major (post-1.0).

## Typed-resource mapping

| Label part | Resource |
|---|---|
| `<prefix>` | `apiVersion` group |
| first segment after prefix | `kind` |
| `.name` | `metadata.name` (default = service name) |
| `.instance` | owner |
| `com.docker.compose.*` | `metadata.labels` |

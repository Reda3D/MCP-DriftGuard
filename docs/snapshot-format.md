# Snapshot format

A snapshot is a static, versioned description of what an MCP server declares.
DriftGuard never produces one by connecting to a server: snapshots are generated
by whatever already knows the server's contract, then treated as untrusted input
here.

- **Format:** JSON, UTF-8, no BOM
- **Current version:** `"1"`
- **Extension:** `.json` by convention
- **Size limit:** 32 MiB
- **Tool limit:** 10 000
- **Schema nesting limit:** 32 levels

---

## Top level

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | string | no (defaults to `"1"`) | Format version. A mismatch is fatal |
| `server` | object | no | Free-form metadata about the server |
| `tools` | array | no (defaults to `[]`) | Declared tools |

Unknown top-level keys are preserved but not interpreted. `server` is recorded
in reports for traceability; it does not affect evaluation.

```json
{
  "schema_version": "1",
  "server": {
    "name": "filesystem-mcp",
    "version": "1.0.0",
    "source": "npm:@acme/filesystem-mcp@1.0.0"
  },
  "tools": []
}
```

---

## Tool

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | **yes** | Unique, non-empty, at most 256 characters |
| `description` | string | no | At most 100 000 characters |
| `input_schema` | object | no (defaults to `{}`) | JSON Schema for the tool's arguments |
| `capabilities` | object | no (defaults to `{}`) | Declared powers, see below |

`name` is Unicode-normalised to NFC on load. Two tools whose names collide after
normalisation are a **fatal error**: a shadowed tool cannot be reviewed reliably.

### Capability vocabulary

Capabilities are what make a drift report actionable. A schema tells you what a
tool accepts; a capability tells you what it can do.

| Capability | Type | Risky direction | Meaning |
|---|---|---|---|
| `read_only` | boolean | `false` | The tool never mutates state |
| `destructive` | boolean | `true` | The tool can destroy data |
| `network_access` | boolean | `true` | The tool can reach the network |
| `filesystem` | enum | higher | `none` < `read` < `write` < `delete` |
| `executes_commands` | boolean | `true` | The tool can run a process |
| `accesses_secrets` | boolean | `true` | The tool can read credentials |

Note the inverted direction on `read_only`: turning it **off** is the escalation.

Any other key is accepted and treated as `true`-is-riskier. An unknown capability
that appears or changes is reported, never ignored — an analyser that cannot rank
a change must not be the component that decides it is harmless.

---

## Canonical hashing

`driftguard hash` prints a SHA-256 over a canonical form of the snapshot:

1. Tools are sorted by NFC-normalised `name`.
2. Each tool is reduced to `{name, description, input_schema, capabilities}`.
3. The document is serialised with sorted keys, `(",", ":")` separators and no
   ASCII escaping.
4. The UTF-8 bytes of that string are hashed.

Consequences worth knowing:

- Two snapshots that differ only in key order or tool order hash identically.
- `server` metadata is **excluded**, so bumping a version string does not change
  the digest of the contract.
- Re-indenting a description does not change the digest, but changing one word
  does.

The digest is what you pin in review: "we approved `5d0898c4…`".

---

## Validation errors

Every one of these is fatal (exit code `2`), with a message naming the offending
location.

| Condition | Why it is fatal |
|---|---|
| Invalid JSON / non-UTF-8 / `NaN` | Silent coercion would change the contract |
| `tools` not an array | Ambiguous document |
| Missing or empty `name` | Unaddressable tool |
| Duplicate `name` | Shadowing: the client may resolve a different definition than the reviewer sees |
| Non-local `$ref` | DriftGuard does not resolve references; following one would be an SSRF primitive |
| Nesting beyond 32 levels | Stack and memory safety |
| `filesystem` not in the enum | Unrankable capability |
| Capability value is an object or array | Unrankable capability |
| `schema_version` mismatch | A newer format may mean something different |

---

## Producing a snapshot

DriftGuard is deliberately agnostic. Three common routes:

1. **From the server's own manifest** — many MCP servers ship a JSON manifest or
   a typed tool registry; map it directly.
2. **From a `tools/list` response**, captured once and committed. Capturing is a
   separate, reviewed step: it is the only moment a server is contacted, and it
   should not happen inside the check that is supposed to constrain it.
3. **By hand** for a small, stable server. Tedious, but it makes the contract
   explicit, which is the point.

Whatever the route, the snapshot is committed to the repository and reviewed
like code. That is what makes the baseline trustworthy.

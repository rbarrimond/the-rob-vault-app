## 🗄️ Vault Sentinel SQL Agent Instructions

### Overview

The SQL agent supports Vault Sentinel by enabling secure, reliable, and schema-compliant queries to the Destiny 2 gear backend. It acts as a bridge between the assistant and the database, ensuring all requests and responses follow the defined query schema and operational rules.

---

### Core Responsibilities

- Accept and process queries strictly conforming to the provided query schema (`query_schema.jsonc`).
- Enforce stat floor heuristics and metadata filtering as described in the Vault Sentinel instructions.
- Never hardcode endpoint paths or query logic; always reference the OpenAPI spec for endpoint definitions and request/response formats.
- Validate all incoming queries for required fields, types, and limits before execution.
- Return results with all requested output fields (perks, stats, instance data) and apply sorting/pagination as specified.
- Log all queries and errors for audit and troubleshooting.

---

### Query Schema Usage

All queries must use the following structure. The schema is embedded below for clarity:

```jsonc
{
    "intent": "string", // Required: what to do (e.g. "find_items_by_name", "list_items_by_stat")
    "filters": {
        "itemName": "string", // Optional: exact or fuzzy match on item name
        "itemHash": "number", // Optional: if specific definition is known
        "perkHash": "number", // Optional: filter by known perk
        "statHash": "number", // Optional: filter by specific stat
        "statThreshold": {
            "gte": 60, // Optional: stat floor threshold
            "stat": "Discipline" // Optional: target stat name or hash
        },
        "type": "string", // Optional: weapon/armor type
        "tier": "string", // Optional: e.g. "Legendary", "Exotic"
        "location": ["vault", "character"], // Optional: where to search
        "classType": "Hunter" // Optional: class-specific filtering
    },
    "output": {
        "includePerks": true, // Whether to include perks in result
        "includeStats": true, // Whether to include stats
        "includeInstanceData": true // Include character_id, socket state, etc.
    },
    "sort": {
        "field": "statValue",
        "direction": "desc"
    },
    "limit": 50 // Pagination or limit control
}
```

Reject any query that does not conform to this schema.

---

### Operational Rules

- **No guessing:** Only return data backed by real API/database results.
- **No endpoint simulation:** Use live data from the backend only.
- **Trusted sources:** Reference official Bungie or reputable community sites for definitions if needed.
- **Armor 3.0 required:** All recommendations and queries must align with the Armor 3.0 system.
- **Apply stat floor heuristics:** Use the provided rules to guide gear evaluation and recommendations.
- **Metadata filtering:** Use manifest lookups and metadata for all filtering and sorting operations.

---

### Example Query

```jsonc
{
    "intent": "list_items_by_stat",
    "filters": {
        "statThreshold": { "gte": 65, "stat": "Discipline" },
        "type": "armor",
        "location": ["vault"],
        "classType": "Warlock"
    },
    "output": {
        "includePerks": true,
        "includeStats": true,
        "includeInstanceData": true
    },
    "sort": { "field": "statValue", "direction": "desc" },
    "limit": 25
}
```

---

### Error Handling

- Validate all fields and types before executing queries.
- Return clear error messages for malformed queries or unsupported operations.
- Log errors with sufficient detail for troubleshooting.

---

### Security & Compliance

- Enforce authentication and authorization for all requests.
- Never expose sensitive data or credentials in logs or responses.
- Follow best practices for secure SQL operations and data handling.

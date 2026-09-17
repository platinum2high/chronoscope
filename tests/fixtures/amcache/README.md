# Amcache fixture

`Amcache.hve` — a real Windows Server 2022 Amcache hive, pulled from a
backup server built for an unrelated (fictional) CTF lab environment.
Not real customer/production data; every host, account, and file path
in it belongs to a made-up scenario.

Ground truth for the test assertions in `src/artifacts/amcache.rs` was
established two ways, independently of this project's own parser:

- `AmcacheParser.exe` (Eric Zimmerman) run against this file, output in
  the categories it reports non-empty data for (`DeviceContainers`,
  `DevicePnps`, `UnassociatedFileEntries`) — used to sanity-check field
  values (names, hashes, paths) during development.
- `impacket.winregistry` (a separate, pre-existing REGF implementation)
  used directly via a Python REPL to enumerate raw key/value counts and
  types — this is what the exact counts asserted in the test (123
  `InventoryApplicationFile` subkeys, 40 `InventoryDevicePnp`, 4
  `InventoryDeviceContainer`) are cross-checked against.

Note the `UnassociatedFileEntries.csv` category from AmcacheParser.exe
(42 rows) is *not* the same number as "all file entries" — it's already
filtered down to files whose `ProgramId` doesn't correlate to an
installed application. This parser intentionally doesn't try to
reproduce that exact filtering; it emits every `InventoryApplicationFile`
entry (123 here) with an `application_name` field that's `"Unassociated"`
when no correlation is found, same idea, own logic.

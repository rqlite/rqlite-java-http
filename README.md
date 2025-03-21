# rqlite-java-http
 A minimal Java client for rqlite, useful on its own or as a foundation for higher-level packages

This library offers support for:

- Executing SQL statements (`INSERT`, `UPDATE`, `DELETE`)
- Running queries (`SELECT`)
- Handling both read and write statements in a single request via the _Unified Endpoint_.
- Backing up and restoring data to your rqlite system
- Booting a rqlite node from a SQLite database file
- Checking node status, diagnostic info, cluster membership, and readiness

 To see the client in action start a rqlite node reachable at http://localhost:4001 and run:
 ```bash
mvn compile
mvn exec:java
```

-- Shared, cross-instance rate-limit counter.
--
-- Each row is one fixed window: (scope, client_key, window_start) → count.
-- `scope` namespaces a limiter (e.g. 'login', 'api'); `client_key` is the
-- client identifier (origin IP, or a SHA-256 digest of the API token);
-- `window_start` is the UNIX epoch second the window began. The request path
-- does one atomic UPSERT that increments and returns the count, so N app
-- instances sharing this database enforce ONE combined limit — and the
-- abuse-sensitive scopes run fail-closed, so the guard is never silently
-- disabled by a limiter DB error.

CREATE TABLE IF NOT EXISTS rate_limit_bucket (
    scope        text    NOT NULL,
    client_key   text    NOT NULL,
    window_start bigint  NOT NULL,
    count        integer NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, client_key, window_start)
);

-- Supports the periodic prune of stale windows (DELETE ... WHERE window_start < cutoff).
CREATE INDEX IF NOT EXISTS idx_rate_limit_bucket_window
    ON rate_limit_bucket (scope, window_start);

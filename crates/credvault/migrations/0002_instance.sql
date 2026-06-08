-- Per-connection instance, for tenant-scoped providers (e.g. Workday) whose authorize/
-- token URLs and API base embed a per-customer host + tenant. The value is a JSON object
-- of the provider's declared instance_vars (e.g. {"host":"…","tenant":"…"}). NULL for
-- ordinary global providers. Captured at authorize time, carried through the callback,
-- and used to template the provider's URLs on every token request and refresh.
ALTER TABLE oauth_flows ADD COLUMN instance TEXT;
ALTER TABLE connections ADD COLUMN instance TEXT;

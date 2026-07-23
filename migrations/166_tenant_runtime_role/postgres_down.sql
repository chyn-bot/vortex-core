-- Non-destructive: leave the role and its grants in place (dropping a role
-- that may own objects or be in use is riskier than leaving it). To fully
-- reverse, an operator revokes grants and drops vortex_runtime out-of-band.
SELECT 1;

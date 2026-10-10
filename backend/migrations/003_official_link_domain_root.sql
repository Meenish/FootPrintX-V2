-- Adds the 'domain_root' official-link kind.
--
-- Most discovered services are not in the verified official-link registry, and
-- those recommendations previously ended with no destination at all ("No
-- verified official link for this service"), which left the user with nothing
-- to act on. A recommendation may now point at the service's own canonical
-- home page, derived from authenticated message evidence rather than from a
-- link inside an email. It is labelled in the UI as a home page and explicitly
-- not as a verified deep link, so it stays distinct from 'settings_page' (a
-- deep link the provider's own documentation uses) and 'help_page' (the
-- provider's official help article).

ALTER TABLE recommendations DROP CONSTRAINT IF EXISTS recommendations_official_url_kind_check;

ALTER TABLE recommendations
  ADD CONSTRAINT recommendations_official_url_kind_check
  CHECK (official_url_kind IN ('settings_page', 'help_page', 'domain_root', 'none'));

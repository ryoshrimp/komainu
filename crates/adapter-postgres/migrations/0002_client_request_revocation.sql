ALTER TABLE grants DROP CONSTRAINT grants_revocation_reason_check;
ALTER TABLE grants ADD CONSTRAINT grants_revocation_reason_check
    CHECK (revocation_reason IN ('code_replay', 'refresh_token_replay', 'client_disabled', 'user_disabled', 'client_request'));

-- Codes and requests created before PKCE carry no challenge; drop them (P-12).
DELETE FROM authorization_codes;
DELETE FROM authorization_requests;

ALTER TABLE authorization_requests
    ADD COLUMN code_challenge text NOT NULL CHECK (char_length(code_challenge) = 43),
    ADD COLUMN code_challenge_method text NOT NULL CHECK (code_challenge_method IN ('S256'));

ALTER TABLE authorization_codes
    ADD COLUMN code_challenge text NOT NULL CHECK (char_length(code_challenge) = 43),
    ADD COLUMN code_challenge_method text NOT NULL CHECK (code_challenge_method IN ('S256'));

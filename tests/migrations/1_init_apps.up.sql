INSERT INTO apps (id, name, secret, redirect_url)
VALUES (1, 'test', 'test-secret', 'http://localhost:3000')
    ON CONFLICT DO NOTHING;
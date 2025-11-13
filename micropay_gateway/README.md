# Test against db

```bash
pg_isready
createdb testdb
psql testdb

psql
CREATE USER testuser WITH PASSWORD 'testpass';
GRANT CONNECT ON DATABASE testdb TO testuser;
GRANT USAGE ON SCHEMA public TO testuser;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO testuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO testuser;


# test connection
PGPASSWORD=testpass psql -h 127.0.0.1 -p 5433 -U testuser testdb

CREATE TABLE test (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO test (name) VALUES ('alice'), ('bob'), ('charlie');

```


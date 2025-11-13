#!/bin/bash
PGPASSWORD=testpass psql "host=127.0.0.1 port=5433 user=testuser dbname=testdb sslmode=disable"

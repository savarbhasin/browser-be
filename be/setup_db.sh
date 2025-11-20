#!/bin/bash

# Script to set up PostgreSQL database for Windsurf URL Checker

echo "Setting up PostgreSQL database..."

# Check if PostgreSQL is running (Docker)
if ! docker ps | grep -q postgres; then
    echo "Starting PostgreSQL with Docker..."
    docker run --name postgres \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        -e POSTGRES_DB=uss-db \
        -p 5432:5432 \
        -d postgres:15
    
    echo "Waiting for PostgreSQL to start..."
    sleep 5
else
    echo "PostgreSQL is already running."
fi

# Create database if it doesn't exist
echo "Creating database if it doesn't exist..."
docker exec -it postgres psql -U postgres -c "CREATE DATABASE uss_db;" 2>/dev/null || echo "Database already exists"

echo "Database setup complete!"
echo ""
echo "Connection string: postgresql://postgres:postgres@localhost:5432/uss_db"
echo ""
echo "To connect to the database:"
echo "  docker exec -it postgres psql -U postgres -d uss_db"


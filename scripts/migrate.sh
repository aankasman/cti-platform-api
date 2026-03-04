#!/bin/bash
#
# Database Migration Script for Rinjani V3
#
# Usage:
#   ./scripts/migrate.sh push      # Push schema changes
#   ./scripts/migrate.sh generate  # Generate SQL migration
#   ./scripts/migrate.sh status    # Check migration status
#   ./scripts/migrate.sh reset     # Reset database (DANGEROUS!)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DB_PACKAGE="$PROJECT_ROOT/packages/db"

# Load environment
if [ -f "$PROJECT_ROOT/.env" ]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env" | xargs)
fi

if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL is not set"
    exit 1
fi

echo "Database: ${DATABASE_URL%%@*}@..."

case "$1" in
    push)
        echo "Pushing schema changes..."
        cd "$DB_PACKAGE"
        npx drizzle-kit push
        echo "✓ Schema pushed successfully"
        ;;
    
    generate)
        echo "Generating migration..."
        cd "$DB_PACKAGE"
        npx drizzle-kit generate
        echo "✓ Migration generated in packages/db/drizzle/"
        ;;
    
    migrate)
        echo "Running migrations..."
        cd "$DB_PACKAGE"
        npx drizzle-kit migrate
        echo "✓ Migrations applied"
        ;;
    
    status)
        echo "Checking migration status..."
        cd "$DB_PACKAGE"
        npx drizzle-kit check
        ;;
    
    reset)
        echo "⚠️  WARNING: This will drop all tables!"
        read -p "Type 'yes' to confirm: " confirm
        if [ "$confirm" = "yes" ]; then
            cd "$DB_PACKAGE"
            npx drizzle-kit drop
            npx drizzle-kit push
            echo "✓ Database reset complete"
        else
            echo "Aborted"
            exit 1
        fi
        ;;
    
    seed)
        echo "Seeding database..."
        cd "$PROJECT_ROOT"
        npx tsx packages/db/src/seed.ts
        echo "✓ Database seeded"
        ;;
    
    *)
        echo "Usage: $0 {push|generate|migrate|status|reset|seed}"
        echo ""
        echo "Commands:"
        echo "  push      Push schema changes to database"
        echo "  generate  Generate SQL migration files"
        echo "  migrate   Run pending migrations"
        echo "  status    Check migration status"
        echo "  reset     Drop and recreate all tables (DANGEROUS!)"
        echo "  seed      Populate database with test data"
        exit 1
        ;;
esac

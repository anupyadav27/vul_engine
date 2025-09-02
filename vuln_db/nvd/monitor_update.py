#!/usr/bin/env python3
import psycopg2
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv('/Users/apple/Desktop/utility/vuln_db/nvd/.env')

# Connect to database
conn = psycopg2.connect(
    host=os.getenv('DB_HOST'),
    port=int(os.getenv('DB_PORT')),
    database=os.getenv('DB_NAME'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD')
)

print(f"🔍 Database Status at {datetime.now().strftime('%H:%M:%S')}:")

with conn.cursor() as cursor:
    # Current CVE count
    cursor.execute("SELECT COUNT(*) FROM cves")
    total_cves = cursor.fetchone()[0]
    
    # CVEs added today
    cursor.execute("""
        SELECT COUNT(*) FROM cves 
        WHERE created_at::date = CURRENT_DATE
    """)
    new_today = cursor.fetchone()[0]
    
    # Latest dates
    cursor.execute("""
        SELECT 
            MAX(published_date) as latest_published,
            MAX(last_modified_date) as latest_modified
        FROM cves 
        WHERE published_date != '1970-01-01 00:00:00'
    """)
    
    result = cursor.fetchone()
    latest_published, latest_modified = result
    
    print(f"  Total CVEs: {total_cves:,}")
    print(f"  New CVEs added today: {new_today:,}")
    print(f"  Latest published: {latest_published}")
    print(f"  Latest modified: {latest_modified}")
    
    # Calculate remaining gap
    if latest_published:
        gap_days = (datetime.now().date() - latest_published.date()).days
        print(f"  Remaining gap: {gap_days} days")

conn.close()
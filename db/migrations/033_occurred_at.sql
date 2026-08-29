-- Add occurred_at column to entries table
-- This allows for sorting by the actual event date (e.g. meeting date)
-- rather than just the created/updated timestamp.

ALTER TABLE entries ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMP WITH TIME ZONE;

-- Create index for efficient sorting
CREATE INDEX IF NOT EXISTS idx_entries_occurred_at_updated_at ON entries (occurred_at DESC, updated_at DESC);

-- Backfill: Extract dates from titles
-- YYYY-MM-DD
UPDATE entries 
SET occurred_at = substring(title from '(\d{4}-\d{2}-\d{2})')::timestamp with time zone
WHERE occurred_at IS NULL 
  AND title ~ '\d{4}-\d{2}-\d{2}';

-- MM-DD-YYYY
UPDATE entries 
SET occurred_at = to_date(substring(title from '(\d{2}-\d{2}-\d{4})')::text, 'MM-DD-YYYY')
WHERE occurred_at IS NULL 
  AND title ~ '\d{2}-\d{2}-\d{4}';

-- DD-MM-YYYY (Last resort)
UPDATE entries 
SET occurred_at = to_date(substring(title from '(\d{2}-\d{2}-\d{4})')::text, 'DD-MM-YYYY')
WHERE occurred_at IS NULL 
  AND title ~ '\d{2}-\d{2}-\d{4}';

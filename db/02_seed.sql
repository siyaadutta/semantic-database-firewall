-- Seed data for meaningful query-plan demonstrations.
-- Source of truth: .kiro/steering/project-instructions.md (§5)
--
-- Row counts are chosen so a sequential scan on an UNINDEXED column
-- (e.g. users.email, orders.status) is measurably different from an
-- index scan on an INDEXED column (primary keys, and the indexes we add
-- at the bottom of this file only for SOME columns on purpose).

-- 100,000 users
INSERT INTO users (email, full_name, country, created_at)
SELECT
    'user' || g || '@example.com',
    'User ' || g,
    (ARRAY['US','GB','DE','IN','BR','JP','FR','CA'])[1 + (g % 8)],
    now() - (g || ' minutes')::interval
FROM generate_series(1, 100000) AS g;

-- 5,000 products
INSERT INTO products (sku, name, category, price_cents, created_at)
SELECT
    'SKU-' || lpad(g::text, 6, '0'),
    'Product ' || g,
    (ARRAY['electronics','books','home','toys','clothing'])[1 + (g % 5)],
    500 + (g % 50000),
    now() - (g || ' hours')::interval
FROM generate_series(1, 5000) AS g;

-- 300,000 orders
INSERT INTO orders (user_id, status, total_cents, created_at)
SELECT
    1 + (g % 100000),
    (ARRAY['pending','paid','shipped','delivered','cancelled'])[1 + (g % 5)],
    1000 + (g % 90000),
    now() - (g || ' minutes')::interval
FROM generate_series(1, 300000) AS g;

-- 600,000 transactions
INSERT INTO transactions (order_id, product_id, quantity, amount_cents, created_at)
SELECT
    1 + (g % 300000),
    1 + (g % 5000),
    1 + (g % 5),
    500 + (g % 50000),
    now() - (g || ' seconds')::interval
FROM generate_series(1, 600000) AS g;

-- Indexes: intentionally add SOME so we can demonstrate index scans,
-- while leaving other columns unindexed to demonstrate sequential scans.
CREATE INDEX idx_orders_user_id ON orders(user_id);
-- NOTE: orders.status is intentionally NOT indexed (seq scan demo).
-- NOTE: users.email is intentionally NOT indexed (seq scan demo);
--       an index recommendation should surface for lookups on it.
CREATE INDEX idx_transactions_order_id ON transactions(order_id);

ANALYZE users;
ANALYZE products;
ANALYZE orders;
ANALYZE transactions;

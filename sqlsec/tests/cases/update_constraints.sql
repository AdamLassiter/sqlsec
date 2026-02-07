.output /dev/null

CREATE TABLE __sec_items (
    id            INTEGER PRIMARY KEY,
    row_label_id  INTEGER NOT NULL,
    name          TEXT
);

INSERT INTO __sec_items VALUES (1, 1, 'Item One');

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_register_table('items', '__sec_items', 'row_label_id', 1, NULL);

SELECT sec_clear_context();
SELECT sec_refresh_views();

.output stdout

.print ------------------------------------------------------------
.print [Attempt to update primary key - should fail]
UPDATE items SET id = 999 WHERE id = 1;

.print ------------------------------------------------------------
.print [Attempt to update row_label_id - should fail]
UPDATE items SET row_label_id = 999 WHERE id = 1;

.print ------------------------------------------------------------
.print [Update name - should succeed]
UPDATE items SET name = 'Updated Item' WHERE id = 1;
SELECT * FROM items;

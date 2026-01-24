.output /dev/null

CREATE TABLE __sec_employees (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER,
    name         TEXT
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');          -- id = 1
SELECT sec_define_label('role=admin');    -- id = 2
SELECT sec_define_label('role=manager');  -- id = 3

-- Register table with insert policy
SELECT sec_register_table(
    'employees',
    '__sec_employees',
    'row_label_id',
    NULL,
    'role=manager'        -- insert policy expression
);
.output stdout

.output /dev/null
SELECT sec_clear_context();
.output stdout

.print ------------------------------------------------------------
.print [Insert default label]
INSERT INTO employees (name) VALUES ('Alice');
SELECT * FROM employees ORDER BY id;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_push_context();
SELECT sec_set_attr('role', 'manager');
.output stdout

.print ------------------------------------------------------------
.print [Insert with context role=manager]
INSERT INTO employees (name) VALUES ('Bob');
SELECT * FROM employees ORDER BY id;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_push_context();
.output stdout

.print ------------------------------------------------------------
.print [Insert with context role=staff (policy ignored)]
SELECT sec_set_attr('role', 'staff');
INSERT INTO employees (name) VALUES ('Charlie');
SELECT * FROM employees ORDER BY id;

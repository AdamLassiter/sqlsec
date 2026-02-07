.output /dev/null

CREATE TABLE __sec_employees (
    id            INTEGER PRIMARY KEY,
    row_label_id  INTEGER NOT NULL,
    name          TEXT,
    department    TEXT,
    salary        INTEGER,
    title         TEXT
);

INSERT INTO __sec_employees VALUES
  (1, 1, 'Alice',   'Engineering', 50000, 'Developer'),
  (2, 1, 'Bob',     'Engineering', 75000, 'Senior Dev'),
  (3, 1, 'Charlie', 'Sales',       60000, 'Rep');

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_define_label('role=manager');
SELECT sec_define_label('role=admin');
SELECT sec_define_label('(role=admin|role=hr)');

SELECT sec_register_table('employees', '__sec_employees', 'row_label_id', 1, NULL);

-- Set column update policies via sec_columns table
UPDATE sec_columns SET update_label_id = sec_define_label('role=manager')
  WHERE logical_table = 'employees' AND column_name = 'salary';
UPDATE sec_columns SET update_label_id = sec_define_label('(role=admin|role=hr)')
  WHERE logical_table = 'employees' AND column_name = 'title';

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'developer');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Developer trying to update name - should succeed]
UPDATE employees SET name = 'Alice Smith' WHERE id = 1;
SELECT id, name, salary, title FROM employees WHERE id = 1;

.print ------------------------------------------------------------
.print [Developer trying to update salary - should fail]
UPDATE employees SET salary = 999999 WHERE id = 1;

.print ------------------------------------------------------------
.print [Developer trying to update title - should fail]
UPDATE employees SET title = 'CEO' WHERE id = 1;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'manager');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Manager trying to update salary - should succeed]
UPDATE employees SET salary = 55000 WHERE id = 1;
SELECT id, name, salary, title FROM employees WHERE id = 1;

.print ------------------------------------------------------------
.print [Manager trying to update title - should fail]
UPDATE employees SET title = 'Lead' WHERE id = 1;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'hr');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [HR trying to update title - should succeed]
UPDATE employees SET title = 'Senior Developer' WHERE id = 1;
SELECT id, name, salary, title FROM employees WHERE id = 1;

.print ------------------------------------------------------------
.print [HR trying to update salary - should fail]
UPDATE employees SET salary = 100000 WHERE id = 1;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin trying to update salary - should fail (needs manager)]
UPDATE employees SET salary = 100000 WHERE id = 1;

.print ------------------------------------------------------------
.print [Admin trying to update title - should succeed]
UPDATE employees SET title = 'Principal Engineer' WHERE id = 1;
SELECT id, name, salary, title FROM employees WHERE id = 1;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_set_attr('role', 'manager');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin+Manager updating both salary and title - should succeed]
UPDATE employees SET salary = 120000, title = 'VP Engineering' WHERE id = 1;
SELECT id, name, salary, title FROM employees WHERE id = 1;

.print ------------------------------------------------------------
.print [Final state of all employees]
SELECT * FROM employees;
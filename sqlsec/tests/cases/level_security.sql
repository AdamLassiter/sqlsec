.output /dev/null

CREATE TABLE __sec_documents (
    id            INTEGER PRIMARY KEY,
    row_label_id  INTEGER NOT NULL,
    title         TEXT,
    content       TEXT,
    classification TEXT
);

INSERT INTO __sec_documents VALUES
  (1, 1, 'Public Notice',      'Everyone can see this',     'public'),
  (2, 2, 'Internal Memo',      'Confidential info here',    'confidential'),
  (3, 3, 'Project Plans',      'Secret project details',    'secret'),
  (4, 4, 'Defense Strategy',   'Top secret material',       'top_secret');

.load ./target/debug/libsqlsec

-- Define clearance levels (higher value = more access)
SELECT sec_define_level('clearance', 'public', 0);
SELECT sec_define_level('clearance', 'confidential', 1);
SELECT sec_define_level('clearance', 'secret', 2);
SELECT sec_define_level('clearance', 'top_secret', 3);

-- Define labels using level comparisons
SELECT sec_define_label('clearance>=public');
SELECT sec_define_label('clearance>=confidential');
SELECT sec_define_label('clearance>=secret');
SELECT sec_define_label('clearance>=top_secret');

SELECT sec_register_table('documents', '__sec_documents', 'row_label_id', NULL, NULL);

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('clearance', 'public');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Public clearance - sees only public]
SELECT id, title, classification FROM documents;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('clearance', 'confidential');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Confidential clearance - sees public + confidential]
SELECT id, title, classification FROM documents;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('clearance', 'secret');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Secret clearance - sees public + confidential + secret]
SELECT id, title, classification FROM documents;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('clearance', 'top_secret');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Top Secret clearance - sees all documents]
SELECT id, title, classification FROM documents;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [No clearance set - sees nothing]
SELECT id, title, classification FROM documents;

# duckdb-hprof

DuckDB extension for querying Java HPROF heap dumps as SQL.

```sql
LOAD 'hprof.duckdb_extension';

SELECT * FROM hprof_scan('dump.hprof', 'header');
SELECT * FROM hprof_scan('dump.hprof', 'strings');
SELECT * FROM hprof_scan('dump.hprof', 'instances');
```

## Tables

| Name | Description |
|---|---|
| `header` | format, id_size, timestamp_ms |
| `strings` | string_id, value |
| `classes` | class_serial, class_object_id, name_string_id |
| `class_dumps` | class layouts: super, loader, instance_size, field counts |
| `instances` | object_id, class_object_id, shallow_size, retained_size |
| `gc_roots` | root_type, object_id, thread_serial, frame_number |
| `heap_summary` | live/alloc bytes and counts |
| `object_arrays` | array_id, index, element_id (exploded) |
| `primitive_arrays` | array_id, element_type, count, bytes |
| `stack_frames` | frame_id, method, source file, line |
| `stack_traces` | trace_serial, thread_serial, frame_count |
| `dominators` | object_id, dominator_id, distance_to_root |

## Examples

```sql
-- Top classes by retained heap
SELECT s.value, count(*), sum(i.shallow_size), sum(i.retained_size)
FROM hprof_scan('dump.hprof', 'instances') i
JOIN hprof_scan('dump.hprof', 'classes') c ON i.class_object_id = c.class_object_id
JOIN hprof_scan('dump.hprof', 'strings') s ON c.name_string_id = s.string_id
GROUP BY s.value ORDER BY sum(i.retained_size) DESC LIMIT 10;

-- Materialize for fast queries
CREATE TABLE inst AS SELECT * FROM hprof_scan('dump.hprof', 'instances');
CREATE TABLE strs AS SELECT * FROM hprof_scan('dump.hprof', 'strings');

-- Path to GC root
WITH RECURSIVE path AS (
    SELECT object_id, dominator_id, 1 as step
    FROM hprof_scan('dump.hprof', 'dominators')
    WHERE object_id = 21470769184
    UNION ALL
    SELECT d.object_id, d.dominator_id, p.step + 1
    FROM hprof_scan('dump.hprof', 'dominators') d
    JOIN path p ON d.object_id = p.dominator_id
)
SELECT * FROM path ORDER BY step;
```

## Build

```sh
make debug      # or make release
```

Load with DuckDB:

```sql
LOAD 'build/debug/hprof.duckdb_extension';
```

select trace_id, span_id, count(*) as duplicate_count
from {{ ref('mart_tool_metrics') }}
group by trace_id, span_id
having count(*) > 1

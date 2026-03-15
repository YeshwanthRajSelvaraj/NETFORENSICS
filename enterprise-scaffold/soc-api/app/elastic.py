import os
from elasticsearch import AsyncElasticsearch

ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")

# Async Elasticsearch client to interface nicely with FastAPI event loops
es_client = AsyncElasticsearch([ES_HOST])

async def search_tenant_flows(tenant_id: str, query: dict, index="nf-flows*"):
    """
    Wrapper function that FORCES tenant scoping on every Elasticsearch query.
    Prevents cross-tenant data leakage by automatically applying a term filter
    matching the user's Organization ID.
    
    If an Analyst asks for "All traffic on port 80", this transparently alters
    it to "All traffic on port 80 AND tenant_id == 'org_xyz'"
    """
    # The absolute tenant boundary constraint
    tenant_filter = {"term": {"tenant_id": {"value": tenant_id}}}
    
    # Intelligently inject the tenant filter into the incoming OpenSearch Query DSL
    if "query" not in query:
        query["query"] = {"bool": {"filter": [tenant_filter]}}
    else:
        # If it's already a boolean query, append to the filter array
        if "bool" in query["query"]:
            if "filter" not in query["query"]["bool"]:
                query["query"]["bool"]["filter"] = []
                
            existing = query["query"]["bool"]["filter"]
            if isinstance(existing, list):
                existing.append(tenant_filter)
            else:
                query["query"]["bool"]["filter"] = [existing, tenant_filter]
        else:
            # Wrap standard queries (e.g., term, match) into a bool MUST context
            original_query = query.pop("query")
            query["query"] = {
                "bool": {
                    "must": [original_query],
                    "filter": [tenant_filter]
                }
            }

    # Execute search against the Elastic cluster
    response = await es_client.search(index=index, body=query)
    return response

async def get_tenant_stats(tenant_id: str):
    """Aggregation query to power the dashboard landing page securely"""
    query = {
        "size": 0,
        "aggs": {
            "total_bytes": {"sum": {"field": "bytes_transferred"}},
            "unique_src_ips": {"cardinality": {"field": "src_ip"}},
            "protocols": {
                "terms": {"field": "protocol", "size": 5}
            }
        }
    }
    return await search_tenant_flows(tenant_id, query)

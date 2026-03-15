import requests
import json
import base64

# Simple HTTP wrapper to hit Elasticsearch 8 API
ES_HOST = "http://localhost:9200"
# NOTE: Using basic auth 'elastic:changeme' if xpack.security is on.

HEADERS = {
    'Content-Type': 'application/json'
}

print("Setting up Elasticsearch ILM Policies and Component Templates...")

#####################################################################
# 1. Setup Index Lifecycle Policy (ILM)
#    Hot for 7 days -> Warm for 30 days -> Delete
#####################################################################
ilm_policy = {
    "policy": {
        "phases": {
            "hot": {
                "actions": {
                    "rollover": {
                        "max_age": "1d",
                        "max_primary_shard_size": "50gb"
                    }
                }
            },
            "warm": {
                "min_age": "7d",
                "actions": {
                    "forcemerge": {"max_num_segments": 1},
                    "shrink": {"number_of_shards": 1}
                }
            },
            "delete": {
                "min_age": "30d",
                "actions": {"delete": {}}
            }
        }
    }
}
r_ilm = requests.put(f"{ES_HOST}/_ilm/policy/nf-flows-policy", json=ilm_policy, headers=HEADERS)
print("ILM Policy Creation: ", r_ilm.status_code, r_ilm.text)

#####################################################################
# 2. Setup Index Template for Flows (Applying ILM & strict types)
#    Mapping `tenant_id` allowing filtering per customer.
#####################################################################
flow_template = {
    "index_patterns": ["nf-flows-*"],
    "template": {
        "settings": {
            "number_of_shards": 3,
            "number_of_replicas": 0, # Since we run single node Dev ES
            "index.lifecycle.name": "nf-flows-policy",
            "index.lifecycle.rollover_alias": "nf-flows"
        },
        "mappings": {
            "properties": {
                "tenant_id": {"type": "keyword"},
                "sensor_id": {"type": "keyword"},
                "ingestion_timestamp": {"type": "date", "format": "epoch_second"},
                "start_time": {"type": "date", "format": "epoch_second"},
                "end_time": {"type": "date", "format": "epoch_second"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "protocol": {"type": "keyword"},
                "bytes_transferred": {"type": "long"}
            }
        }
    }
}

r_tmpl = requests.put(f"{ES_HOST}/_index_template/nf-flows-template", json=flow_template, headers=HEADERS)
print("Flow Template Creation: ", r_tmpl.status_code, r_tmpl.text)

#####################################################################
# 3. Setup Index Template for Alerts
#    Alerts have a different lifecycle (keep for 1 year)
#####################################################################
alert_template = {
    "index_patterns": ["nf-alerts-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
        },
        "mappings": {
            "properties": {
                "tenant_id": {"type": "keyword"},
                "engine_name": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "mitre_techniques": {"type": "keyword"},
                "affected_ips": {"type": "ip"}
            }
        }
    }
}
r_tmpl2 = requests.put(f"{ES_HOST}/_index_template/nf-alerts-template", json=alert_template, headers=HEADERS)
print("Alert Template Creation: ", r_tmpl2.status_code, r_tmpl2.text)

print("\nEnterprise Data Lake Initialized.")

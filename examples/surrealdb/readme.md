# Dsiem deployment with Vector

This directory stores two Docker compose environment:

- [compose.yml](./compose.yml): Dsiem environment that uses vector and surrealdb, instead of Logstash & Elasticsearch.
- [compose-with-es.yml](./compose-with-es.yml): also uses vector and surrealdb, but also stores copy of alarms in Elasticsearch.

The vector configs are the same. Processing flow for the central node is given in the image below, which was produced using this command:

```sh
docker exec vector vector graph --config-dir /etc/vector/ | dot -Tsvg > graph-central.svg
```
![central vector](./graph-central.svg)

And for the side-car vector:

![side-car vector](./graph-sidecar.svg)


## Example queries

- Get all alarms with events:
  
  ```sql
  SELECT alarm_id, title, risk_class, (SELECT event, stage FROM alarm_event WHERE alarm = $parent.id) AS events FROM alarm
  ```
  Using `curl` and `jq`:

  ```shell
  curl -s \
    -H 'content-type: application/json' -H 'accept: application/json' \
    -H 'NS: default' -H 'DB: dsiem' \
    -XPOST "http://localhost:8000/sql" \
    -d'select alarm_id, title, risk_class, (SELECT event, stage from alarm_event WHERE alarm = $parent.id) as events from alarm' | jq .
  ```
- Get a specific alarm and specific rule stage:
  ```sql
  SELECT alarm_id, title, risk_class, (SELECT event, stage FROM alarm_event WHERE alarm = $parent.id and stage = 1) AS events FROM alarm where alarm_id="quMQXSHQR"
  ```
  Example output:
  ```json
  [
    {
      "result": [
        {
          "alarm_id": "quMQXSHQR",
          "events": [
            {
              "event": "event:⟨f24a6763-9dbd-4309-b420-f24323684c2e⟩",
              "stage": 1
            }
          ],
          "risk_class": "Medium",
          "title": "Ping Flood from 192.168.144.68"
        }
      ],
      "status": "OK",
      "time": "55.358211ms"
    }
  ]
  ```
- Get all details of the event(s) as well:

  ```sql
  SELECT alarm_id, title, risk_class, (SELECT event, stage FROM alarm_event WHERE alarm = $parent.id and stage = 1) AS events FROM alarm where alarm_id="quMQXSHQR" fetch events.event
  ```
  Result:
  ```json
  [
    {
      "result": [
        {
          "alarm_id": "quMQXSHQR",
          "events": [
            {
              "event": {
                "@timestamp": "2024-04-06T07:16:03.361840551Z",
                "category": "Misc activity",
                "custom_data1": "...f.....^...................... !\"#$%&'()*+,-./01234567",
                "custom_label1": "payload printable",
                "dst_ip": "192.168.100.1",
                "dst_port": 0,
                "event_id": "f24a6763-9dbd-4309-b420-f24323684c2e",
                "id": "event:⟨f24a6763-9dbd-4309-b420-f24323684c2e⟩",
                "index_name": "siem_events",
                "plugin_id": 1001,
                "plugin_sid": 2100384,
                "product": "Intrusion Detection System",
                "protocol": "ICMP",
                "sensor": "9615aa703dba",
                "src_ip": "192.168.144.68",
                "src_port": 0,
                "timestamp": "2024-04-06T07:16:03.155401+0000",
                "title": "GPL ICMP_INFO PING"
              },
              "stage": 1
            }
          ],
          "risk_class": "Medium",
          "title": "Ping Flood from 192.168.144.68"
        }
      ],
      "status": "OK",
      "time": "57.704647ms"
    }
  ]
  ```

## Cleanup database function

`dsiem-esproxy` creates `dsiem_cleanup($min_age: duration)` database function if it doesn't yet exist on surrealdb. This function can be executed to help maintain data consistency and remove records that are no longer in use.

Because of the way Dsiem works, `alarm_event` and `event` records will be created prior to the associated `alarm`, which itself may not ever be created if its risk value stays below 1. Triggered alarms (risk ≥ 1) may also be archived somewhere else and deleted from the database afterwards.

Taking those into account, `dsiem_cleanup()` is then designed to delete these records:

  - `alarm` whose stage 1 rule doesn't have associated events.
    
    These alarms must have been intentionally deleted by a user/admin, but still have their backlog active in dsiem backend.
  - `alarm_event` that have no associated `alarm`.
  
    This condition can happen because the backlog's risk is still < 1, or the alarm had been deleted. To avoid deleting the former, the function will only delete `alarm_event` records whose timestamp is older than `$min_age` (supplied in a form of duration, e.g. `1d`, `3h`, `1s`, `4w`). That parameter therefore should be set long enough to avoid deleting entries for active backlogs whose risk is still < 1.
  - `event` that have no associated `alarm`.
  
    Similar with `alarm_event`, `$min_age` should be set long enough to avoid deleting entries for active backlogs whose risk is still < 1.

Example execution of `dsiem_cleanup()` using `curl`:

  ```shell
  # will delete the following:
  # - alarm records that have no event
  # - alarm_event records that have no alarm and is older than 1 day
  # - event records that have no alarm and is older than 1 day

  curl -s \
    -H 'content-type: application/json' -H 'accept: application/json' \
    -H 'NS: default' -H 'DB: dsiem' \
    -XPOST "http://localhost:8000/sql" \
    -d'fn::dsiem_cleanup(1d)' | jq .
  ```

  Result:
  ```json
  [
    {
      "result": {
        "deleted": {
          "alarm": 0,
          "alarm_event": 0,
          "event": 31
        }
      },
      "status": "OK",
      "time": "44.317581ms"
    }
  ]
  ```
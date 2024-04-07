# Dsiem ES proxy

This tool replaces Logstash in Dsiem architecture by:

- Implementing the [scripted upsert](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-update.html#scripted_upsert) functionality in [80_siem.conf](https://github.com/defenxor/dsiem-rs/blob/90945c2f5d5be15070b74d5a71f7dca6eff919ea/deployments/docker/conf/logstash/conf.d/80_siem.conf#L119), which is meant to avoid inserting duplicate entries for the same alarm into Elasticsearch, and to avoid updating `status` and `tag` fields if they've been updated through other means (e.g. Dsiem UI).

- Upserting the default `siem_alarms` [index template](https://github.com/defenxor/dsiem-rs/blob/master/deployments/docker/conf/logstash/index-template.d/es7/siem_alarms-template.json) to Elasticsearch when there isn't one already exist.

An example of Dsiem architecture that completely replaces Logstash with [Vector](https://vector.dev/) is shown in the diagram below. There is a docker compose deployment for it in [here](./examples/elasticsearch/). The vector config files in particular have comments that further explain the setup.

```mermaid
flowchart TB

v3 -->|suricata alerts|es
v3 -->|normalized events|es
v3 -->|normalized events|df
ep -->|alarms|es

db -->|alarm_events|es
db -->|alarms|ep

s1 -->|eve.json|v3
s2 -->|syslog|v3

df -->|events through NATS|db

subgraph "Vector (Central)"
 v3[vector]
end

subgraph Source logs
 s1[suricata]
 s2[random_netdevice]
end

subgraph Elasticsearch cluster
 es[nodes]
end

subgraph Dsiem frontend
 ep[dsiem-es-proxy]
 df[frontend]
end

subgraph Dsiem backend
 db[backend + vector]
end

```

## How to test the example

- Clone this repo:

  ```shell
  git clone https://github.com/mmta/dsiem-esproxy.git
  ```
- Start the docker compose environment (replace `eth0` with appropriate network interface):
  ```shell
  cd examples/elasticsearch
  export PROMISC_INTERFACE=eth0
  docker compose up
  ```
- From another terminal in the same host, install Kibana dashboard:
  ```shell
  cd examples/elasticsearch
  ./kbndashboard-import.sh localhost ./kibana/dashboard-siem.json 
  ```
- From another terminal in the same host, ping an external IP, and make sure the traffic goes through that network interface (e.g. `eth0`).
  ```shell
  ping 1.1.1.1
  ```
- Open Kibana dashboard from http://localhost:5601, and verify that ping related alarms are created in the Dsiem dashboard.

## Surrealdb version

There is another example that also replace Elasticsearch with Surrealdb in [here](./examples/surrealdb/).

- Activate the compose environment: 

  ```shell
  cd examples/surrealdb
  export PROMISC_INTERFACE=eth0
  docker compose up
  ```

- From another terminal in the same host, ping an external IP, and make sure the traffic goes through that network interface (e.g. `eth0`).

  ```shell
  ping 1.1.1.1
  ```

- After that, visit https://surrealist.app/ and use it to connect to:

  - Endpoint: http://localhost:8000
  - Namespace: default
  - Database: dsiem
  - Authentication: Anonymous

## Misc Info

- Docker image is available from [dockerhub](https://hub.docker.com/r/mmta/dsiem-esproxy). Refer to the compose example on how to use it, and the CLI `--help` parameter to see all the valid arguments.

- Use or review the [Dockerfile](./Dockerfile) on how to build the project.
  ```shell
  docker build . -t mmta/dsiem-esproxy
  docker run --rm mmta/dsiem-esproxy --help
  ```

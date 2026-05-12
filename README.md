# BICEP Maltrail Image

Maltrail image wrapper for BICEP. This repository adapts the upstream `ghcr.io/stamparm/maltrail` image to the IDS plugin interface used by BICEP and exposes the usual configuration, custom-trails, static-analysis, and network-analysis endpoints.

## What changed from the Snort sample

- The runtime now launches Maltrail's `sensor.py` instead of Snort.
- Uploaded IDS configs are treated as `maltrail.conf` files and are patched so logs always land in `/opt/logs`.
- The `ruleset` upload is mapped to Maltrail custom trails and stored in `CUSTOM_TRAILS_DIR`.
- Parsed alerts now come from Maltrail's daily event logs rather than `alert_fast.txt`.

## Build locally

```bash
cd ./bicep-maltrail
docker buildx build . \
  --build-arg BASE_IMAGE=ghcr.io/stamparm/maltrail \
  --build-arg VERSION=1.4 \
  -t ghcr.io/bicep-pump/bicep-maltrail:latest \
  --no-cache
```

## CI/CD

- Pushes run the plugin test suite in `bicep-maltrail/src/tests`.
- Scheduled, merged, or manually dispatched publish workflows build from the latest upstream Maltrail release tag and push the wrapper image to GHCR.

## Notes for BICEP usage

- Maltrail needs a valid `maltrail.conf`. A starter example is included at [bicep-maltrail/maltrail.conf](/home/max/Masterarbeit/BICEP-maltrail/bicep-maltrail/maltrail.conf).
- Live analysis updates `MONITOR_INTERFACE` to the BICEP-managed tap interface before launching the sensor.
- Static analysis runs Maltrail in offline mode with `sensor.py -r <pcap>`.

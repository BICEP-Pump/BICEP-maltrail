<div align="center">
<a href="https://github.com/BICEP-Pump/BICEP-maltrail/pkgs/container/bicep-maltrail"><img alt="Container Registry" src="https://img.shields.io/badge/GHCR-bicep--maltrail-blue?style=for-the-badge&logo=github"></a>
<img alt="Codecov" src="https://img.shields.io/codecov/c/github/BICEP-Pump/BICEP-maltrail?style=for-the-badge">
<img alt="GitHub branch status" src="https://img.shields.io/github/checks-status/BICEP-Pump/BICEP-maltrail/main?style=for-the-badge&label=Tests">

<br>

</div>

# BICEP-maltrail
Maltrail Docker image adapted for BICEP.

The image holds the dependencies and IDS plugin interface implementation needed to run Maltrail inside the BICEP application. It supports BICEP configuration uploads, custom trail uploads, static PCAP analysis, and live network analysis through Maltrail's `sensor.py`.

The main BICEP project is available [here](https://github.com/maldwg/BICEP/tree/main) <br>
The official Maltrail repository can be found [here](https://github.com/stamparm/maltrail)

## Usage

If you want to use the resulting image with the BICEP framework, provide a valid `maltrail.conf` configuration. During analysis, the wrapper applies the runtime values that BICEP expects: Maltrail writes logs to `/opt/logs`, live analysis uses the BICEP-managed tap interface, and static analysis uses `any` while reading the uploaded PCAP.

Custom rules uploaded through BICEP are treated as Maltrail custom trails. They are stored in `/tmp/custom-trails/custom_trails.txt`, and the wrapper patches `CUSTOM_TRAILS_DIR` into the active configuration when custom trails are present.

A starter configuration is included at [bicep-maltrail/maltrail.conf](bicep-maltrail/maltrail.conf).

## Initialize project

In order to be able to start the project you will need to initialize it first. Do this by running:

```bash
git submodule update --init --recursive
```

This fetches the newest version of the submodule for the backend code and is necessary for the application to work seamlessly.

## Building the project

To build a local version of the image for testing purposes, run:

```bash
cd ./bicep-maltrail
docker buildx build . \
  --build-arg BASE_IMAGE=ghcr.io/stamparm/maltrail \
  --build-arg VERSION=1.4 \
  -t ghcr.io/bicep-pump/bicep-maltrail:latest \
  --no-cache
```

Change the version to your desired upstream Maltrail version.

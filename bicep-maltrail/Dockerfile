ARG BASE_IMAGE
ARG VERSION

FROM ${BASE_IMAGE}:${VERSION}

RUN mkdir -p /opt/code
WORKDIR /opt/code

COPY ./requirements.txt /opt/code/requirements.txt
COPY ./src/ /opt/code/src
COPY ./apt-requirements.txt /tmp/apt-requirements.txt
COPY ./maltrail.conf /opt/maltrail/maltrail.conf

RUN apt-get update && apt-get install -y python3-pip && xargs apt-get install -y < /tmp/apt-requirements.txt && rm -rf /var/lib/apt/lists/*
RUN pip3 install -r requirements.txt

ENV IDS_MODULE=src.models.maltrail
ENV IDS_CLASS=Maltrail
ENV MALTRAIL_DEFAULT_CONFIG_LOCATION=/opt/maltrail/maltrail.conf
ENV MALTRAIL_CONFIGURATION_LOCATION=/tmp/configuration/maltrail.conf
ENV MALTRAIL_LOG_DIRECTORY=/opt/logs
ENV MALTRAIL_CUSTOM_TRAILS_DIR=/tmp/custom-trails

CMD ["/bin/bash", "-c", "fastapi dev /opt/code/src/main.py --host 0.0.0.0 --port ${PORT}"]

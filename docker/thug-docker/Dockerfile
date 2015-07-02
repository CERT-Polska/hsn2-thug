FROM honeynet/thug

# Configure the database

COPY *.deb /tmp/

RUN apt-get update && apt-get install -f -y --no-install-recommends python-pika python-protobuf && dpkg -i /tmp/*.deb

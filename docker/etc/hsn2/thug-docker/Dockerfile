FROM honeynet/thug

# Configure the database

COPY *.deb /tmp/
COPY start.sh /
COPY logging.conf /opt/thug/src/Logging/

RUN apt-get update && apt-get install -f -y --no-install-recommends python-pika python-protobuf python-magic mongodb && dpkg -i /tmp/*.deb 

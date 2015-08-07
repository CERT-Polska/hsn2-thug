FROM honeynet/thug

# Configure the database

COPY *.deb /tmp/
COPY start.sh /

RUN apt-get update && apt-get install -f -y --no-install-recommends python-pika python-protobuf mongodb && dpkg -i /tmp/*.deb 

FROM honeynet/thug

# Configure the database

COPY *.deb /tmp/
COPY start.sh /

RUN apt-get update && apt-get install -f -y --no-install-recommends python-pika python-protobuf mongodb && pip install pip install pymongo==3.0.3 && dpkg -i /tmp/*.deb 

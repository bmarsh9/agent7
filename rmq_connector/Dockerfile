# install base
FROM ubuntu

# update the operating system:
RUN apt-get update
RUN apt install -y python3-pip nano net-tools sudo sqlite3 libpq-dev

# copy the folder to the container:
ADD . /rmq_connector

# Define working directory:
WORKDIR /rmq_connector

# Install the requirements
RUN pip3 install -r /rmq_connector/requirements.txt

# default command: run the web server
CMD ["python3","connector.py"]

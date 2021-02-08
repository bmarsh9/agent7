# install base
FROM ubuntu

# update the operating system:
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt install -y python3-pip supervisor nginx redis-server nano libpq-dev postgresql postgresql-contrib net-tools sudo

# copy the folder to the container:
ADD . /agent7

# Define working directory:
WORKDIR /agent7

# Install the requirements
RUN pip3 install -r /agent7/requirements.txt

# Setup RabbitMQ
RUN /bin/bash /agent7/setup_rabbitmq.sh

# expose tcp port 5000
#EXPOSE 5000

# default command: run the web server
CMD ["/bin/bash","run.sh"]

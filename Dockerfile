# install base
FROM ubuntu

# update the operating system:
RUN apt-get update --fix-missing && apt-get install -y apt-transport-https
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt install -y python3-pip nginx nano libpq-dev net-tools sudo postgresql-client unzip

# copy the folder to the container:
ADD . /agent7

# Define working directory:
WORKDIR /agent7

# Install the requirements
RUN pip3 install -r /agent7/requirements.txt

# expose tcp port 5000
#EXPOSE 5000

# default command: run the web server
CMD ["/bin/bash","run.sh"]

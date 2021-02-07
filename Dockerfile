# install base
FROM ubuntu

# update the operating system:
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt install -y python3-pip supervisor nginx redis-server nano libpq-dev postgresql postgresql-contrib net-tools sudo systemd

# copy the folder to the container:
ADD . /

# Define working directory:
WORKDIR /agent7

# Install the requirements
RUN pip3 install -r requirements.txt

# expose tcp port 5000
#EXPOSE 443

# default command: run the web server
#CMD ["python3","manage.py","runserver","-h","0.0.0.0"]
#CMD ["/bin/bash"]
#CMD ["/usr/local/bin/uwsgi", "--ini", "start.ini"]
CMD ["/bin/bash","run.sh"]

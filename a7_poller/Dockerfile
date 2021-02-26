# install base
FROM ubuntu

# update the operating system:
RUN apt-get update --fix-missing && apt-get install -y apt-transport-https
RUN apt install -y python3-pip nano net-tools sudo libpq-dev

# copy the folder to the container:
ADD . /a7_poller

# Define working directory:
WORKDIR /a7_poller

# Install the requirements
RUN pip3 install -r /a7_poller/requirements.txt

# default command: run the web server
CMD ["python3","poller.py"]


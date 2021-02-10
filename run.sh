cp ./server_config/docker/default /etc/nginx/sites-available/
cp ./server_config/docker/start.ini /agent7

service nginx restart

/bin/bash ./server_config/setup_db.sh db1

python3 manage.py init_db

unzip ./app/commands/ip_db.zip -d ./app/commands/
psql postgresql://db1:db1@postgres_db:5432/db1 -c "\copy iplocation from './app/commands/IP2LOCATION-LITE-DB5.CSV' delimiter ',' csv;"

/usr/local/bin/uwsgi --ini start.ini

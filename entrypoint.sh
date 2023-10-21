#!/bin/sh

# Activate the pipenv virtual environment
. $(pipenv --venv)/bin/activate

while ! pipenv run python manage.py migrate  2>&1; do
   echo "Migration is in progress status"
   sleep 3
done

echo "Migration Complete."

# Start the Django application using Gunicorn --test
pipenv run gunicorn --bind 0.0.0.0:8000 getknowtifyd.wsgi:application
FROM python:3.11-slim-buster

ENV PYTHONBUFFERED=1

WORKDIR /gntfapi

RUN apt-get update && apt-get install -y \
  default-libmysqlclient-dev \
  pkg-config \
  gcc \
  pkg-config \
  && rm -rf /var/lib/apt/lists/*

RUN pip install pipenv

COPY Pipfile Pipfile.lock /gntfapi/

RUN pipenv install --deploy --ignore-pipfile

COPY . .

EXPOSE 8000


RUN chmod +x /gntfapi/entrypoint.sh

ENTRYPOINT ["/gntfapi/entrypoint.sh"]
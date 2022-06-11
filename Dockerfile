FROM tiangolo/meinheld-gunicorn-flask:python3.9

RUN pip3 install requests

COPY ./app /app

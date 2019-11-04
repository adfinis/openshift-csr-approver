FROM python:3

LABEL maintainer="toni.tauro@adfinis-sygroup.ch"

ADD main.py /main.py
ADD requirements.txt /requirements.txt

RUN chmod +x /main.py && pip install -r requirements.txt

ENTRYPOINT /main.py

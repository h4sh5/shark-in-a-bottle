FROM python:3.10-slim-bullseye
RUN apt update; apt install -y tshark
RUN useradd sharky; mkdir /app; chown sharky /app
RUN mkdir /home/sharky; chown sharky /home/sharky

COPY /requirements.txt /app/
USER root
RUN pip3 install -r /app/requirements.txt


USER sharky
WORKDIR /app
COPY /app.py /app/
# COPY /templates /app
RUN mkdir /app/templates
COPY /templates /app/templates
# COPY /templates/ /app/templates
COPY /LICENSE /app
COPY /start.sh /app
RUN mkdir /app/uploads

EXPOSE 5000
ENTRYPOINT /app/start.sh
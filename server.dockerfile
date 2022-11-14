FROM openjdk:11

RUN mkdir "/app"

WORKDIR "/app"

COPY "noteme/build/"

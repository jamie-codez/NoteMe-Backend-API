FROM openjdk:11

ENV VERTICLE_NAME noteme.jar
ENV VERTICLE_HOME /app

WORKDIR "/app"

COPY build/libs/$VERTICLE_NAME $VERTICLE_HOME
ENTRYPOINT ["sh","-c"]
CMD ["exec java -jar $VERTICLE_NAME"]

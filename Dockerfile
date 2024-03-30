FROM --platform=linux/amd64 python:3.7-alpine
FROM amazoncorretto:11-alpine3.19 as builder
ARG MSVC_NAME=msvc-users
WORKDIR /app/$MSVC_NAME
COPY .mvn ./.mvn
COPY ./mvnw .
COPY pom.xml .
RUN ./mvnw clean package -Dmaven.test.skip -Dmaven.main.skip -Dspring-boot.repackage.skip && rm -r ./target
COPY ./src ./src
RUN ./mvnw clean package -DskipTests
FROM amazoncorretto:11-alpine3.19
ENV PORT 8001
EXPOSE ${PORT}
WORKDIR /app
RUN mkdir ./logs
COPY --from=builder /app/msvc-users/target/msvc-users-0.0.1-SNAPSHOT.jar .
CMD ["java", "-Djdk.tls.client.protocols=TLSv1.2", "-jar", "msvc-users-0.0.1-SNAPSHOT.jar"]
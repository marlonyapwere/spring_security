FROM maven:3.8.4-openjdk-17 AS build
WORKDIR /app
COPY pom.xml ./
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn package -DskipTests

FROM openjdk:17-jdk-alpine
WORKDIR /app
LABEL maintainer="marlone@kaributech-ai.com"
WORKDIR /app
COPY --from=build /app/target/security-0.0.1-SNAPSHOT.jar /app/security-0.0.1-SNAPSHOT.jar

EXPOSE 8072
ENTRYPOINT ["java", "-jar", "/app/security-0.0.1-SNAPSHOT.jar"]
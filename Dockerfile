# === Build stage ===
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app
COPY . .
RUN ./gradlew clean bootJar --no-daemon


# === Run stage ===
FROM eclipse-temurin:21-jre
WORKDIR /opt/app
COPY --from=build /app/build/libs/*-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/opt/app/app.jar"]
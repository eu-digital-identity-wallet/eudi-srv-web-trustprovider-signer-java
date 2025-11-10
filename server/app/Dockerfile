# Stage 1: Build Java Backend with Maven
# 1. Pulling the dependencies
FROM maven:3.8.5-eclipse-temurin-17 AS java_builder
# Change working directory in the container
WORKDIR /opt/app
# Copy all POMs first for better build caching
COPY ../pom.xml .
COPY ../app/pom.xml ./app/pom.xml
COPY ../sa/pom.xml ./sa/pom.xml
COPY ../csc/pom.xml ./csc/pom.xml

# Copy source code
COPY ../app/src ./app/src
COPY ../sa/src ./sa/src
COPY ../csc/src ./csc/src

# compile code in /opt/app
RUN mvn -B -e clean install -DskipTests

# Stage 2: Prepare Java Runtime Image
# 3. Preparing the runtime environment
FROM eclipse-temurin:17 AS java_runtime

WORKDIR /opt/app

COPY ../issuersCertificates ./issuersCertificates

COPY --from=java_builder /opt/app/app/target/*.jar /app.jar
EXPOSE 8082
ENTRYPOINT ["java", "-jar", "/app.jar"]

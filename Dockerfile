FROM maven:3.9.3 AS build
# Download maven and name that part of instruction as build

    WORKDIR /app
    # Create new folder /app and create an application here
    
    ARG CONTAINER_PORT
    # Create environment variable CONTAINER_PORT
    
    COPY pom.xml /app
    # Copy pom.xml file into /app folder
    
    RUN mvn dependency:resolve
    # Run mavn dependency:resolve to download all dependencies
    
    COPY . /app
    # Copy everything into /app folder
    
    RUN mvn clean
    RUN mvn package -DskipTests -X
    # Now we have application.jar file in doacker

# End of build part of instruction


FROM openjdk:20
# Download maven

    COPY --from=build /app/target/*.jar app.jar
    # Just renaming asdfasdf.jar into app.jar
    
    EXPOSE 80
    # Open port 80
    
    CMD ["java", "-jar", "app.jar"]
    # Run java -jar app.jar

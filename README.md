[![Build Status](https://travis-ci.com/ravinder5/easyiam.svg?branch=master)](https://travis-ci.com/ravinder5/easyiam)

### Pre-requisites

For running this application in your local you must have below tools installed in your server:
1) Java 11 or above
2) Docker ( for running cassandra instance)

### Instructions to run locally
1) Make sure `Docker` is up and running
2) go to application folder `cd {user}/easy_iam`
3) execute `./gradlew clean build`
4) execute `docker-compose up`. This will start embedded cassandra with required key_space and Tables
5) execute `java -jar build/libs/easy_iam-0.0.1-SNAPSHOT.jar`

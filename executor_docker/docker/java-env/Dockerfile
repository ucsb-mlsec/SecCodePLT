FROM openjdk:17-jdk-slim

# install necessary packages
RUN apt-get update && apt-get install -y \
    maven \
    curl \
    coreutils \
    bc \
    python3 \
    vim \
    bash \
    && rm -rf /var/lib/apt/lists/*

# set up workspace
WORKDIR /workspace

# create maven project template and pre-download dependencies
COPY pom.xml /workspace/
RUN mvn dependency:go-offline -q

RUN mkdir -p /workspace/src/main/java/juliet/support
RUN mkdir -p /workspace/juliet-support/src/main/java/juliet/support

# COPY juliet-support and dataset
COPY juliet-support/ /workspace/src/main/java/juliet/support/
COPY juliet-support/ /workspace/juliet-support/src/main/java/juliet/support/
COPY dataset/ /workspace/dataset/

# pre compile the juliet-support code
RUN cd /workspace && mvn compile -q

# execute tests
COPY compile-and-test.sh /usr/local/bin/
COPY compile-and-test-patch.sh /usr/local/bin/
COPY test-runner.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# environment variables
ENV MAVEN_OPTS="-Xmx512m"
ENV JAVA_TOOL_OPTIONS="-Xmx512m"
ENV JAVA_HOME=/usr/local/openjdk-17
ENV PATH="$JAVA_HOME/bin:$PATH"

RUN mkdir -p /tmp/java-eval

CMD ["/bin/bash"]
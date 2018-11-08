FROM openjdk:8u181-jdk-slim
COPY dist/* /usr/src/myapp/
WORKDIR /usr/src/myapp
ENV USERNAME ""
ENV REGION ""
ENV TIME "60"
CMD java -jar onelogin-aws-cli.jar -u $USERNAME -a 359949 -d statpro -r $REGION -s -l 10 -t $TIME
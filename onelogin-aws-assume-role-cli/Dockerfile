FROM openjdk:8u181-jdk-slim
COPY dist/* /usr/src/myapp/
WORKDIR /usr/src/myapp
ENV USERNAME ""
ENV ACCOUNT "359949"
ENV SUBDOMAIN "statpro"
ENV REGION ""
ENV LOOP "10"
ENV TIME "60"
CMD java -jar onelogin-aws-cli.jar -u $USERNAME -a $ACCOUNT -d $SUBDOMAIN -r $REGION -s -l $LOOP -t $TIME
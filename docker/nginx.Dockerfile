FROM nginx:1.21.4-alpine

RUN apk add --update --no-cache bash

COPY docker/conf/nginx.conf /etc/nginx/nginx.conf

COPY hios /usr/bin/hios
RUN chmod +x /usr/bin/hios

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /tmp/.sdwan

ENTRYPOINT ["/entrypoint.sh"]
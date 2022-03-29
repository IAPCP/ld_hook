FROM debian:bullseye
COPY ./build.sh /root/build.sh
COPY ./ /root/binutils-2.38/
RUN apt update && \
    apt install git build-essential bison flex texinfo libsqlite3-dev uuid-dev libcjson-dev sqlite3 -y && \ 
    chmod +x /root/build.sh
CMD ["/bin/bash"]
FROM scratch
COPY encrok /encrok
ENV ENCROK_PORT=3000
EXPOSE 3000 3001
ENTRYPOINT ["/encrok", "--proxy"]

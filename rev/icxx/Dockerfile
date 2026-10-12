FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN addgroup -S -g 10001 icx && adduser -S -D -H -u 10001 -G icx icx
WORKDIR /app
COPY --chmod=0555 icx-emu run.sh /app/

USER icx:icx
EXPOSE 1337
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD /bin/busybox wget -q -O /dev/null http://127.0.0.1:1337/health || exit 1
ENTRYPOINT ["/app/run.sh"]

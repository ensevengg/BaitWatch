FROM python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d
RUN apk add --no-cache bash ca-certificates curl git make nodejs npm \
    && git config --system --add safe.directory /repo
RUN python -m compileall -q /usr/local/lib/python3.12
USER 65532:65532

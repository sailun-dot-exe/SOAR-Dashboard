# Attack simulator: hydra + helpers for brute-force / reachability checks.
FROM alpine:3.20
RUN apk add --no-cache hydra openssh-client netcat-openbsd curl bash
COPY users.txt passwords.txt /wordlists/
CMD ["sleep", "infinity"]

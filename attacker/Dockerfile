FROM alpine:3.20

# Base image is pinned. Package versions are NOT: `apk add` resolves to
# whatever the alpine:3.20 repository currently serves, so an image built
# a year from now may not be byte-identical. This is a documented trade-off
# (see README > Known Limitations). To pin them, run:
#   docker exec attacker apk info -v | grep -E '^(nmap|curl|iputils)-'
# and paste the exact versions as  nmap=<ver> curl=<ver> iputils=<ver>.

RUN apk add --no-cache nmap curl iputils

CMD ["sleep", "infinity"]

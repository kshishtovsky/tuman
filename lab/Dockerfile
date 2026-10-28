# Стенд DPI: privileged + NET_ADMIN нужны для netns/tc/nft и NFQUEUE.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 nftables tcpdump iperf3 curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY dpi/ /lab/dpi/
COPY netns.sh test_rules.py /lab/
RUN chmod +x /lab/netns.sh

# pcap для офлайн-прогонов монтируется в /lab/captures
VOLUME ["/lab/captures"]
CMD ["bash"]

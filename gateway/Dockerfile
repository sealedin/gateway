# Bakes the proxy config into the pinned LiteLLM image: a dstack host receives only a compose file and an env file,
# so there is no repo checkout to bind-mount the config from. The pin policy is docs/litellm-pin.md.
FROM ghcr.io/berriai/litellm@sha256:d1da6edc025e6a59be6faa50b4e8e42c115e1c99644aa3fc2ac416dd353f41da
COPY config.yaml request_guard.py /
# The wrapper derives LITELLM_MASTER_KEY from the guest agent inside the CVM, then execs the stock entrypoint.
COPY entrypoint.py /entrypoint.py
ENTRYPOINT ["python3", "-I", "/entrypoint.py"]
# One worker: the request guard's count of running requests lives in this process's memory.
CMD ["--config", "/config.yaml", "--port", "4000", "--num_workers", "1"]

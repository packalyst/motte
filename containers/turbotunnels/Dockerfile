FROM python:slim-bookworm

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr so logs (incl. the auth-failure
# markers the firewall jail consumes) are emitted immediately.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Only turbo-tunnel is needed (it pulls in tornado). No Flask/pyyaml/psutil:
# there is no control server and no config file any more.
# PINNED: the auth fix works by overwriting this package's https.py below, so
# the version must match the file we ship. Bump both together, deliberately.
RUN python3 -m pip install --no-cache-dir turbo-tunnel==0.19.0

# App files.
COPY run.py https.py socks.py /app/

# Replace turbo_tunnel's HTTP and SOCKS5 handlers with our patched copies:
#  - https.py enforces proxy auth on both CONNECT and plain-HTTP and logs events
#  - socks.py adds the same connection/auth-failure log markers for SOCKS5
# Both use package-relative imports, so they must live inside the installed
# turbo_tunnel package (they are not standalone plugins).
RUN TT=$(python3 -c 'import turbo_tunnel, os; print(os.path.dirname(turbo_tunnel.__file__))') \
 && cp /app/https.py "$TT/https.py" \
 && cp /app/socks.py "$TT/socks.py"

# Run as an unprivileged user (NO sudo, NO root). The proxy only binds the
# configured high ports and needs no privilege.
RUN adduser --disabled-password --gecos '' turbotunnels \
 && chown turbotunnels:turbotunnels /app

USER turbotunnels

CMD ["python3", "run.py"]

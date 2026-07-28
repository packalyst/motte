FROM python:slim-bookworm

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python deps system-wide (available to the unprivileged user below).
RUN python3 -m pip install --no-cache-dir turbo-tunnel pyyaml flask flask-httpauth psutil

# Run as an unprivileged user (NO sudo). The proxy binds only high ports
# (3128/1080/5000) and writes its config under /app, so root is never needed.
RUN adduser --disabled-password --gecos '' turbotunnels \
 && chown turbotunnels:turbotunnels /app

# App files, owned by the runtime user so gen_config can (re)write tunnels.yaml.
COPY --chown=turbotunnels:turbotunnels gen_config.py tunnels.default.json launch_tunnels.py https.py /app/

USER turbotunnels
CMD python3 launch_tunnels.py

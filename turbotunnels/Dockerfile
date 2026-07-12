FROM python:slim-bookworm

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user

RUN apt-get update \
 && apt-get install -y sudo
RUN adduser --disabled-password --gecos '' turbotunnels
RUN adduser turbotunnels sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN python3 -m pip install turbo-tunnel pyyaml flask flask-httpauth psutil
COPY gen_config.py /app/
COPY tunnels.default.json /app/
COPY launch_tunnels.py /app/
COPY https.py /app/
CMD python3 launch_tunnels.py
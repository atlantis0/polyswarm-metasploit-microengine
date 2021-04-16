FROM polyswarm/polyswarm-client:2

# -- Remove polyswarm-client Source from Base Image ----
RUN mv /usr/src/app /usr/src/psc \
 && mkdir -p /usr/src/app/docker \
 && cp -a /usr/src/psc/docker/*_keyfile /usr/src/app/docker/ \
 && rm -rf /usr/src/psc

WORKDIR /usr/src/app

# -- Install Prerequisites -----------------------------
COPY requirements.txt .
RUN set -x && pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y unzip

# CUSTOMIZE_HERE
# This is where you would copy you scanner backend binary into the Docker image, e.g.:
# COPY myscanner.bin .


# -- Copy & Install Participant ------------------------
COPY . .
RUN python setup.py install

CMD ["microengine", "--backend", "addis_addis"]


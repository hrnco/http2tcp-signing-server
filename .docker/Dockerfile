FROM php:8.4-apache

# Enable Apache modules commonly needed for PHP apps.
RUN a2enmod rewrite headers

# Install openssl CLI for key generation via shell_exec.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /var/www/html

# Persistent storage for generated keys.
VOLUME ["/keys"]

# Copy application source.
COPY . /var/www/html

# Set recommended permissions for Apache runtime.
RUN chown -R www-data:www-data /var/www/html

COPY .docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN rm -rf /var/www/html/.docker

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 80

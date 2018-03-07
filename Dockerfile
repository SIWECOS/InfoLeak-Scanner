FROM php:5.6-apache

# Install and run composer
RUN apt-get update \
    && apt-get install -y wget git zip unzip \
    && rm -rf /var/lib/apt/lists/* \
    && wget https://raw.githubusercontent.com/composer/getcomposer.org/1b137f8bf6db3e79a38a5bc45324414a6b1f9df2/web/installer -O - -q | php -- --quiet \
    && mv composer.phar /usr/bin/composer && chown www-data: /var/www -R

COPY ./ /var/www/html/

USER www-data

WORKDIR /var/www/html

USER root

RUN composer install



EXPOSE 80

FROM php:8.3-fpm

# Install system packages required for building PHP extensions
RUN apt-get update && apt-get install -y \
    libzip-dev \
    libxml2-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libcurl4-openssl-dev \
    libonig-dev \
    libexif-dev \
    unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install \
        pdo \
        pdo_mysql \
        gettext \
        zip \
        xmlwriter \
        gd \
        curl \
        exif \
    && docker-php-ext-enable exif \
    && apt-get clean && rm -rf /var/lib/apt/lists/*


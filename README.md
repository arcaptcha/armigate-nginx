# ARMigate Nginx Module

Before the regular Nginx process, the module makes a call to the ARMigate API using a keep-alive connection.

Depending on the API response, the module will either block the query or let Nginx continue the regular process.
The module has been developed to protect user experience as if any error was to occur during the process or if the timeout was reached, the module would automatically disable its blocking process and allow those requests.

## Installation

You can install ARMigate Nginx module from source files as described below.

#### Prerequisite

In order to build ARMigate Nginx module, the following packages should be installed:

```shell
apt-get update
apt-get -y install wget gcc make libpcre3-dev libssl-dev zlib1g zlib1g-dev gnupg2 libgeoip-dev libgd-dev libxslt1-dev libxml2-dev libssl-dev
apt-get autoremove
```

#### install.sh:

```shell
armigate_version=v0.0.1-beta
# Create a temporary directory to work in
tmp_dir=$(mktemp -d -t armigate-XXXXXXXXXX)
echo $tmp_dir

# Get the Nginx version in use
nginx_version=$(nginx -v 2>&1 | grep -oP 'nginx\/\K([0-9.]*)')

# Download and untar the Nginx sources to compile dynamic module
curl -sLo ${tmp_dir}/nginx-${nginx_version}.tar.gz http://nginx.org/download/nginx-${nginx_version}.tar.gz
tar -C ${tmp_dir} -xzf ${tmp_dir}/nginx-${nginx_version}.tar.gz

# Download and untar module sources
curl -sLo ${tmp_dir}/armigate_nginx_module.tar.gz https://github.com/arcaptcha/armigate-nginx/archive/refs/tags/${armigate_version}.tar.gz
tar -C ${tmp_dir} -zxf ${tmp_dir}/armigate_nginx_module.tar.gz

# Get the name of the module directory
armigate_dir=$(basename $(ls ${tmp_dir}/armigate-nginx-* -d1))

# Get the compilation flags used during the compilation of nginx, and remove any --add-dynamic-module flag we find
# This is important because when compiling the modules, you have to use the same flags that have been used when compiling nginx
nginx_flags="$(nginx -V 2>&1 | grep -oP 'configure arguments: \K(.*)' | sed -e 's/--add-dynamic-module=\S*//g')"
echo $nginx_flags

# Launch the nginx configure script with same flags + the ARMigate dynamic module
cd ${tmp_dir}/nginx-${nginx_version} && eval "./configure --add-dynamic-module=../${armigate_dir} ${nginx_flags}"

# Compile the modules
make -C ${tmp_dir}/nginx-${nginx_version} -f objs/Makefile modules

# Ensure Nginx module directory is created
mkdir -p /etc/nginx/modules

# Copy the .so modules to nginx configuration
cp ${tmp_dir}/nginx-${nginx_version}/objs/ngx_http_armigate_*.so /etc/nginx/modules/

# Then you have to add the following configuration to your nginx.conf file:
# load_module /etc/nginx/modules/ngx_http_armigate_auth_module.so;
# load_module /etc/nginx/modules/ngx_http_armigate_shield_module.so;

# Ensure the modules are good
nginx -t
```

### Docker

// todo

## Configuration

After going through the installation process (you already have nginx and armigate in your system) it is now you can use
modules in `nginx.conf`:

```
load_module /etc/nginx/modules/ngx_http_armigate_auth_module.so;
load_module /etc/nginx/modules/ngx_http_armigate_shield_module.so;

http {
  [...]
  
  resolver 8.8.8.8;
  upstream armigate {
    server roz.arcaptcha.co:80;
    keepalive 10;
  }

  server {
    [...]
  
    armigate_auth @armigate;

    location = @armigate {
      armigate_shield_key "KEY_PROVIDED_BY_ARCAPTCHA";
      proxy_pass http://armigate/v1/roz/inspect;
      proxy_method POST;
      proxy_http_version 1.1;
      proxy_set_header Connection "keep-alive";
      proxy_set_header Host "roz.arcaptcha.co";
      proxy_set_header Content-Type "application/x-www-form-urlencoded";
      proxy_set_header X-Armigate-X-Set-Cookie $armigate_header_x_set_cookie;
      proxy_set_body $armigate_request_body;
      proxy_ignore_client_abort on;
      proxy_connect_timeout 500ms;
      proxy_read_timeout 500ms;
    }
  }
}
```

### Settings

| Setting                           | Description                                                                                                 | Required | Default               |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------|----------|-----------------------|
| armigate_shield_key               | your ARMigate Secret key	                                                                                   | &check;  |                       |
| armigate_auth_uri_regex           | processes only matching URIs. <br> Note: should be added to the server block but outside the location block |          |                       |
| armigate_auth_uri_regex_exclusion | ignores all matching URIs. <br> Note: should be added to the server block but outside the location block    |          | exclude static assets |
| proxy_connect_timeout             | timeout set for the initial opening connection                                                              |          | 150ms                 |
| proxy_read_timeout                | timeout set for regular API calls	                                                                          |          | 50ms                  |

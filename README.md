# Maintained xhprof for PHP 7.0, 7.1, 7.2 and 7.3

## Install

### Compile in Linux
```
$ /$PHP7/bin/phpize
$ ./configure --with-php-config=/$PHP7/bin/php-config
$ make && make install
```
edit php.ini, add a new line:
```
extension=xhprof.so
```
make sure it works:
```
php -m |grep xhprof
```

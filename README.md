# Maintained xhprof for PHP 7.0, 7.1, 7.2 and 7.3

## Install

### Compile in Linux
```
$ cd extension/
$ phpize
$ ./configure [--with-php-config=/path/to/php-config]
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

## Profile your page

Add the following, as early as possible, to your initial PHP script:
```php
xhprof_enable();

register_shutdown_function(
    function () {
        file_put_contents("/tmp/" . uniqid() . ".ApplicationName.xhprof", serialize(xhprof_disable()));
    }
);
```

## Look at the results:

Make sure `xhprof_html` directory is reachable from your web application and reach the page `xhprof_html/index.php` to see a list of profiles.

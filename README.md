
`mod_evil` is an Apache2 module that contains backdoor functionality.

## Notice 

See [OST.md](OST.md) for OST notice and detections.

## Building

First, edit the macro variables to fit your needs, and the module name after `AP_MODULE_DECLARE_DATA`. 

Install `apxs` and `make` for your Linux distro and compile with:

```
make
```

This will compile the `.so` shared library file, as well as hash the file into `mod_evil_hashes.txt`

## Notes

* Be sure `PrivateTmp` is off for best evil effects, otherwise writing to the filesystem is very limited.



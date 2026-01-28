# arbextract

## usage:
### Linux
```shell
./arbextract-x86_64-linux <xbl_config.img>
```
### Android
```shell
./arbextract-aarch64-android <xbl_config.img>
```
#### Directly what is flashed on the phone
```shell
./arbextract-aarch64-android /dev/block/bootdevice/by-name/xbl_config_a
./arbextract-aarch64-android /dev/block/bootdevice/by-name/xbl_config_b
```

### Windows
```shell
arbextract-x86_64-windows.exe <xbl_config.img>
```

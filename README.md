# obscura

## Example

```shell
$ obscura <(echo 'secret snowflake') > secret.enc
Password:
$ obscura -d secret.enc
Password:
secret snowflake
```

## Install

### pip

```shell
$ pip install obscura
```

### Arch Linux

There is an AUR package available here:
https://aur.archlinux.org/packages/obscura

If you do not know how to install AUR packages on Arch Linux, please consult
the [wiki](https://wiki.archlinux.org/title/Arch_User_Repository)

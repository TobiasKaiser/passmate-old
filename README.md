# Passmate

![Screenshot](doc/passmate.png)

This is a cross-platform, open-source password manager with the following features:
- Synchronization and secure storage on the sync server. For storage on the sync server, your passwords are AES256-encrypted with a random key. 
	- Either use the public available sync server `sync.passmate.net` or set up your own (it's a small Python script).
	- The first time you connect to a sync server, a new 'account' is created for you. If you want to connect to that account on another computer, you have to enter the sync key for that account. The sync key contains the AES256 encryption key and an independent account number. The sync key is quite long, but I have decided that a robust and secure approach is more important for me than convenience at this point.
	- All your passwords are stored as a single 4kB-padded chunk on the server, to keep traceable meta-data to a minimum. 
	- When synchronizing, merge-conflicts are resolved on the client side automatically and fine-granular (down to each field in a record) based on timestamps. 
- The password storage on your local computer is encrypted as well. Because the master password is a potentially dangerous attack vector, the key for the local storage is derived from your master password using the [scrypt](https://www.tarsnap.com/scrypt.html) key derivation function. This is important so that attackers that get hold of your local storage file (e. g. when you lose a device), do not have an easy time cracking your password.

## Documentation

For detailed documentation, please have a look in the doc/ subfolder.

## Releases

Go to https://github.com/TobiasKaiser/passmate/releases to download source code and binary distributions for your operating system.
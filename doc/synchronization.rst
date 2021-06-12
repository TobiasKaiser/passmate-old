.. _Sync:
Synchronization
===============

To synchronize your Passmate :ref:`database <DB>` across multiple systems, synchronize the shared folder (see :ref:`paths <paths>`) using a tool of your choice.

Example synchronization solutions:

- `Syncthing <https://syncthing.net/>`_
- `Unison <https://www.cis.upenn.edu/~bcpierce/unison/>`_
- NFS
- SMB
- `sshfs <https://github.com/libfuse/sshfs>`_
- A cloud service of your choice such as `NextCloud <https://nextcloud.com/>`_ / WebDAV

Every participating host creates and writes an own file in the synchronization folder. All other files in the synchronization folder are only opened for reading. If updates are found in the files from remote hosts, they are applied to the local database.

The files in the synchronization folder follow the :ref:`container format <Security>` chosen for your local database container.

If different passphrases are used for containers on different hosts, you will be prompted for the remote host passphrase during synchronization. If the same passphrase is chosen on all hosts, the passphrase does not need to be re-entered during synchronization. If you want to change your passphrase, you need to repeat this process on each hosts separately.
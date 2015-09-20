
# remoteu2f - Use U2F for PAM remotely

[remoteu2f](http://blitiri.com.ar/p/remoteu2f) is a project that enables the
use of a [FIDO U2F](https://www.yubico.com/applications/fido/) security key
remotely, through a lightly-trusted proxy.

It is useful mainly to use as a second factor authentication for ssh and
sudo-over-ssh. For example:

 - User does "ssh server", and enters their password.
 - Server shows a one-time randomly generated URL.
 - User visits the URL, and inserts/touches the security key.
 - The SSH server allows access.

It is written in Go, with some C for PAM integration.

For how to install and use it, please see the
[installation instructions](INSTALL.md).


## Contact

If you want to report bugs, send patches, or have any questions or comments,
just let me know at albertito@blitiri.com.ar.


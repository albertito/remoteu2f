
# Installing remoteu2f


## Building and installing the proxy

You will need a publicly available server, a valid SSL certificate, and two
open ports (one for HTTP and another one for GRPC).

First, build and install the binary:

    mkdir remoteu2f; cd remoteu2f
    export GOPATH=$PWD

    go get blitiri.com.ar/go/remoteu2f/remoteu2f-proxy
    sudo cp bin/remoteu2f-proxy /usr/local/bin/


Then, generate some random tokens that will be used to authorize clients:

    ( for i in `seq 1 10`; do
          head -c60 /dev/urandom | sha256sum -b | cut -d ' ' -f 1 ;
      done ) > /etc/remoteu2f-proxy/tokens

Use one token per user, or one token per (user, host).
Never share tokens between different users, this is very insecure and will
become even more so in the future.
Tokens are arbitrary strings, prepending the name of the user can help you
know who you gave them to.


Finally, launch the binary. You can use the provided upstart or systemd
examples to help you with this, depending on your system.


## Building and installing the sshd side

You will need `pam_prompt_exec.so` and `remoteu2f-cli`:

    mkdir remoteu2f; cd remoteu2f
    export GOPATH=$PWD

    go get blitiri.com.ar/go/remoteu2f/remoteu2f-cli
    sudo cp bin/remoteu2f-cli /usr/local/bin/

    cd src/blitiri.com.ar/go/remoteu2f/libpam
    make
    sudo cp pam_prompt_exec.so /lib/security



### Configuring sshd

Configure PAM for ssh (or sudo, or the service of your choice) by editing
`/etc/pam.d/sshd` (or equivalent) and adding the following at the bottom:

    auth required pam_prompt_exec.so /usr/local/bin/remoteu2f-cli pam --nullok


sshd itself requires the following configuration settings to work properly.
You can usually set them in `/etc/ssh/sshd_config`:

    UsePAM yes
    ChallengeResponseAuthentication yes


### Configuring a user

Once you have completed the server install above, each each user that wants to
use remoteu2f has to configure their account.

Run `remoteu2f-cli init` and follow the instructions.

Take note of the backup codes so you can access without your security key in
an emergency.


Then use `remoteu2f-cli register` to register your security key. You can
register as many keys as you want.

Use `remoteu2f-cli auth` to verify that it works.


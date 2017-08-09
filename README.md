# RBLGrey: Greylisting on RBL (DNS blacklist) for Postfix

**This application was forked from https://github.com/develersrl/rblgrey and all core rbl check functions are from there.**

This application utilises RBL (DNS Blacklists) and Greylisting in a unique way by only Greylisting clients who happen to be on one of the RBL lists that are checked during execution. The reason this is better than standard greylisting is because it allows the majority of e-mail to go through without delay and only singles out those who are either on a blacklist for a very good reason or simply there accidentally.

Information on the original application where this was forked from and how it came to be, can be found here:
[blog post](http://giovanni.bajo.it/post/47121521214/grey-on-black-combining-greylisting-with-blacklists).


## Installation

Install rblgrey somewhere on the local Postfix filesystem, for instance:

```sh
cd /usr/local
git clone https://github.com/devopper/rblgrey 
```

Create the `rblgrey` user:

```sh
adduser --home=/var/spool/postfix/rblgrey --ingroup=nogroup --shell=/usr/sbin/nologin
```

Create the database using the 'schema.sql' file provided:

```sh
mysql -uroot -p < schema.sql
```

Create a database user, for example:

```sh
mysql -uroot -p
grant all on rblgrey.* to 'rblgrey'@'localhost' identified by 'password';
flush privileges;
```

Edit the configuration file (`/usr/local/rblgrey/rblgrey.conf`) as needed. All defaults are meant
to be reasonable and correct, but you are welcome to change them if you want.

Now, tell Postfix to start rblgrey as a service, by editing `/etc/postfix/master.cf` and adding
this line to it:

```conf
# greylisting on rbl
rbl_grey unix  -       n       n       -       0       spawn
        user=rblgrey argv=/usr/local/rblgrey/rblgrey.py --config /usr/local/rblgrey/rblgrey.conf
```

Then, in `/etc/postfix/main.cf`, within the section `smptd_recipient_restrictions`, add the
following line:

```conf
check_policy_service unix:private/rbl_grey
```

Finally, reload postfix:

```sh
/etc/init.d/postfix restart
```

## Example of full anti-spam configuration

For instance, the following section shows a sample anti-spam configuration with several rules:

```conf
smtpd_recipient_restrictions =
        permit_mynetworks
        permit_sasl_authenticated
        permit_dnswl_client list.dnswl.org
        reject_rbl_client sbl.spamhaus.org
        reject_rbl_client psbl.surriel.com
        reject_unauth_destination
        reject_unlisted_recipient
        check_policy_service unix:private/rbl_grey
```

This is what happens, step by step:

* If the client's IP is in `mynetworks`, mail is delivered.
* If the client has authenticated, mail is delivered.
* If the client's IP is in the <dnswl.org> whitelist, mail is delivered.
* If the client's IP is in either the [Spamhaus SBL](http://www.spamhaus.org/sbl/) or
  [PSBL](http://psbl.org/) blacklists, the mail is rejected (500).
* If the mail destination's domain is not directly handled by Postfix, mail is rejected (=
  disable relay).
* If the mail destination's email is not a valid email address, mail is rejected.
* Otherwise, the mail is handled by rblgrey; it will check whether the client's IP is in one of
  the configured RBLs

## Choosing a Blacklist

The default configuration of rblgrey includes the following blacklists:

 * [xbl.spamhaus.org](http://www.spamhaus.org/xbl/): list of hijacked PCs (aka "zombies")
 * [pbl.spamhaus.org](http://www.spamhaus.org/pbl/): list of consumer IP ranges, that shouldn't
   run mail servers
 * [bl.spamcop.net](http://www.spamcop.net): list of IPs which sent spam (as reported by a large
   community of volunteers)
 * [dnsbl.sorbs.net](http://www.sorbs.net): list of IPs which sent spam to a set of honeypots /
   spam traps

In our experience, outright rejection of email through these blacklists would be too harsh, while
their usage within rblgrey achieves a very good balance.

## To run the test

To run the test, simply execute the following in the rblgrey directory (please note, you're best starting with an empty database and separate copy of rblgrey before continuing):

```sh
python -m pytest test_rblgrey.py
```

SamsungCardAuth
===============

This program allows you to authenticate your Samsung SD card or USB flash drive
to see whether it's a genuine Samsung product in a cross-platform manner.

Usage
-----
- `SamsungCardAuth.Console -l`: Lists the disks you can authenticate.
- `SamsungCardAuth.Console <path to disk>`: Authenticate the given disk. The
  disk must be present in the list of disks.

Authentication result is printed to console. The program returns `0` for
successful authentication, `1` for failed authentication, and a negative
number for a number of other conditions.

Commentary
----------
I got a new Samsung EVO Select microSD card the other day, and looking at
the packaging, I noticed that there's an "authentication available" mark
on the back. I looked around for what that might mean, and found Samsung's
Memory Card/UFD Authentication Utilty. I thought it might be interesting to
figure out how it actually does this. After some tracing, I found the
authentication is done entirely through read operations. It's somewhat
clever, since authentication will never cause data to be overwritten if the
card does not support the protocol, and there are no special ioctls to
cause weird things to happen. However, because HMAC is used for,
authentication, and it requires knowledge of the key by both the sender and
the receipient, the same keys need to be present in both the card and the
program, and not just on one end or the other, meaning the secrets are fully
exposed. This means if someone has a card controller that they can reprogram
with custom code, they could easily reimplement the protocol and include
the key tables and successfully match the response expected by the program,
making the entire scheme rather pointless.

If you'd like to try the original utility, you can get it
[here](https://www.samsung.com/semiconductor/minisite/ssd/download/tools/#download_tab_0101_anchorpar7-st_semi_down_list_ex).
It's quite weird that this is the only place I could find the utility, and
it doesn't even look like a part of the main site. The program dates at the
end of 2019 as of when this was written, so it's an actively maintained
program, yet it's so obscure. Very odd.

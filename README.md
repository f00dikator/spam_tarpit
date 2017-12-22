# spam_tarpit
pretends to be an SMTP server and once client tries to send data, slides recv window down to 0 and holds the connection open...basically fsck with scanners or spammers

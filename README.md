About Koboli
============
Koboli is an email response gateway for Nagios and Icinga (and possibly
other monitoring systems, with some minor work). Its goal is to allow
administrators and operations teams to take action on alerts immediately,
by allowing you to respond directly to an alert without ever leaving your
mail client.

Today, Koboli allows you to perform some basic Nagios-side interaction with
your alerts (enabling/disabling notifications, adding comments, acknowledging
alerts). It can also create issues in JIRA. It was designed to be extremely
simple to extend, and you are encouraged to add your own command handlers!

Koboli was the name of a mail sorter in The Legend of Zelda: The Wind Waker.

Koboli currently lives at:

    https://github.com/jgoldschrafe/koboli


Requirements
============
- Python 2.5+
- ConfigObj
- email_reply_parser
- json
- pytz
- tzlocal
- validate


Installation
============
`koboli.ini` and `kobolispec.ini` go under `/etc/koboli`. `koboli.py` goes
wherever you feel like putting it.


Setup
=====
Koboli is intended to be run upon receipt of a message; this is typically done
by configuring Koboli to run via Procmail or by configuring the MTA on your
system with an alias pointing to the script.

Sendmail
--------
These instructions assume that your Sendmail instance is already configured to
accept SMTP connections from outside mail hosts, and that this configuration is
tested and working.

  1. Place koboli or a symlink to koboli under your smrsh directory
     (this will usually be `/etc/smrsh/koboli`)
  2. Edit your aliases file (typically `/etc/aliases`)
  3. Add a line into your aliases file (replace "nagios") with the appropriate
     username for your environment:

         nagios: "|/etc/smrsh/koboli"

  4. Regenerate your aliases file with newaliases


Usage
=====
The following commands are baked into the initial release:

- `#acknowledge [comment]`: Acknowledge the alert.
- `#comment`: Add a comment in Nagios.
- `#create-issue [description]`: Create a JIRA issue. The full text of the
  original alert will be included in the issue description.
- `#disable-notifications`: Disable notifications for the host or service in
  Nagios.
- `#enable-notifications`: Enable notifications for the host or service in Nagios.


Bundled Command Processors
==========================
- `JIRACommandProcessor`: Creates JIRA issues from 
- `NagiosCommandProcessor`: Translates commands into Nagios command-file entries


License
=======
Copyright (c) 2012, Jeff Goldschrafe <jeff@holyhandgrenade.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  - Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  - Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Additional Components
=====================
### BufferedSMTPHandler
Copyright 2001-2002 by Vinay Sajip. All Rights Reserved.

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Vinay Sajip
not be used in advertising or publicity pertaining to distribution
of the software without specific, written prior permission.
VINAY SAJIP DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
VINAY SAJIP BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#!/usr/bin/env python

import copy
import datetime
import email
from email.utils import parseaddr
import logging
import logging.handlers
from pprint import pprint, pformat
import re
import smtplib
import string
import sys
import time
import traceback

from configobj import ConfigObj
from email_reply_parser import EmailReplyParser
import json
import pytz
from tzlocal import get_localzone
from validate import Validator

# For JiraCommandProcessor
import requests

import __main__


class BufferingSMTPHandler(logging.handlers.BufferingHandler):
    """Replacement for SMTPHandler that buffers log messages.

    Add log messages to a buffer and send them as one single SMTP
    message when the buffer is flushed, rather than sending each one
    individually like the SMTPHandler in Python's standard library.

    """
    def __init__(self, mailhost, fromaddr, toaddrs, subject,
                 capacity = 5000):
        self.mailhost = mailhost
        self.mailport = None
        self.fromaddr = fromaddr
        self.toaddrs = toaddrs
        self.subject = subject

        # BufferingHandler is an old-style object
        logging.handlers.BufferingHandler.__init__(self, capacity)

    def flush(self):
        """Flush buffers and send all buffered messages via SMTP.
        """
        if len(self.buffer) > 0:
            try:
                port = self.mailport
                if not port:
                    port = smtplib.SMTP_PORT

                smtp = smtplib.SMTP(self.mailhost, port)
                fmt = "From: {fromaddr}\r\nTo: {toaddrs}\r\nSubject: {subject}\r\n\r\n{content}"
                msg = fmt.format(
			fromaddr=self.fromaddr,
                        toaddrs=self._join_addrs(self.toaddrs),
                        subject=self.subject,
                        content="\r\n".join(self.format(r) for r in self.buffer))

                smtp.sendmail(self.fromaddr, self.toaddrs, msg)
                smtp.quit()
            except:
                self.handleError(None)  # no particular record

            self.buffer = []


    def _join_addrs(self, addrs):
        """Join a list of addresses using the RFC822 address separator.

        If provided a list of email addresses, return a string
        containing those email addresses separated by commas. If
        provided a string, return that string only.

        """
        if type(addrs) == list:
            return ','.join(addrs)
        else:
            return addrs


class ConfigError(Exception):
    """Raised when a parsed configuration is invalid.
    """
    pass


class EventDataError(Exception):
    """Raised when event data cannot be parsed from a message.
    """
    pass


class CommandProcessor(object):
    """Base class for command processors.

    Provides a list of commands that the processor can respond to,
    and facilities to dispatch commands to handler methods inside the
    processor object.

    """
    def __init__(self, config, event_data):
        self.config = config
        self.event_data = copy.copy(event_data)

    def get_handled_commands(self):
        """Return a list of registered commands that this responds to.
        """
        return self.handled_commands.keys()

    def handle_command(self, command, data):
        """Dispatch a command to the appropriate handler method.
        """
        (opts, data) = self._parse_options(data)
        log.debug('Handling command: {command}'.format(
                command=command))
        self.handled_commands[command](opts, data)

    def _parse_options(self, data):
        """Parse inline option flags from a command string.

        Parse data in any of the following formats: key, key:value,
        key:"quoted value". Returns a tuple (opts, data) containing
        the parsed options and the unparsed remainder of the line.

        """
        if data is None:
            return ({}, '')

        # Match tags of formats: #option, #option:arg,
        # #option:"quoted arg"
        expr = re.compile("#(\w+)(?::(\w+|\"[^\"]\")?)?")
        matches = expr.findall(data)
        data = expr.sub('', data).strip()
        opts = dict(matches)

        return (opts, data)


class EchoCommandProcessor(CommandProcessor):
    """Processor that echoes back a received message."

    Used for basic testing only.

    """
    def __init__(self, config, event_data):
        self.handled_commands = {'echo': self._echo_handler}

        super(EchoCommandProcessor, self).__init__(config, event_data)

    def _echo_handler(self, command, data):
        log.info(self.event_data['message'])


class JiraCommandProcessor(CommandProcessor):
    def __init__(self, config, event_data):
        self.handled_commands = {'create-issue': self._create_issue_handler}

        super(JiraCommandProcessor, self).__init__(config, event_data)

        self.event_data['fqdn'] = '{hostname}.{domain}'.format(
                hostname=self.event_data['hostname'],
                domain=self.config['domain'])

    def _create_issue_handler(self, opts, data):
        """Handle the #create-issue command.

        Check to see if an issue in JIRA has already been created for
        this event. If no duplicate is found, create an issue.

        """
        rest_endpoint = self.config['rest_endpoint']
        url = '/'.join([rest_endpoint, 'issue'])

        username = self.config['username']
        password = self.config['password']
        issue_type = self.config['issue_type']
        project_key = self.config['project_key']

        headers = {'Content-Type': 'application/json'}

        # Create JSON skeleton
        payload = {
            'fields': {
                'description': self._get_issue_description(opts, data),
                'issuetype': {
                    'name': issue_type
                },
                'project': {
                    'key': project_key
                },
                'summary': self._get_issue_summary(opts, data)
            }
        }

        # Then merge in custom fields as defined in configuration file
        fields = self.config.get('fields', {})
        for (name, tmpl) in fields.items():
            payload['fields'][name] = self._format(tmpl,
                                                   **self.event_data)

        if self._duplicate_alert_exists(payload):
            log.error('Duplicate alert exists; not creating.')
            return

        log.debug("Posting to {url}: {payload}".format(url=url,
                 payload=json.dumps(payload)))

        result = requests.post(url, auth=(username, password),
                               data=json.dumps(payload),
                               headers=headers)

        if len(result.json.get('errors', [])) > 0:
            log.error('Failed to create JIRA issue: ' + result.text)
        else:
            key = result.json.get('key', '')
            log.info('Created JIRA issue: {key}'.format(key=key))

    def _duplicate_alert_exists(self, payload):
        """Check whether a duplicate alert already exists in JIRA.

        Currently unimplemented. Returns False always.

        """
        return False

    def _format(self, value, **kwargs):
        """Format a list of arguments.

        If value is a list, return every item in value formatted with
        variables substituted from **kwargs. If value is a string,
        return the result of value.format(**kwargs).

        """
        if type(value) == list:
            return [s.format(**kwargs) for s in value]
        else:
            return value.format(**kwargs)

    def _get_issue_description(self, opts, data):
        parts = [data, self.event_data['alert']]
        parts = [part for part in parts if part != '']
        return "\n\n---\n\n".join(parts)

    def _get_issue_summary(self, opts, data):
        if self.event_data['type'] == 'service':
            tmpl = self.config['service_summary']
        else:
            tmpl = self.config['host_summary']

        return tmpl.format(**self.event_data)

    def _query(self, jql):
        """
        Run a JQL query against JIRA and return the JSON result.

        Currently unimplemented.
        """
        return None


class NagiosCommandProcessor(CommandProcessor):
    """Translates email commands into Nagios commands.

    Maintains a set of Nagios commands, their type signatures, and
    sensible default arguments. Processes email commands and writes
    the appropriate Nagios commands into the Nagios command file.

    """
    def __init__(self, config, event_data):
        self.handled_commands = {'acknowledge': self._acknowledge_handler,
                                 'comment': self._comment_handler,
                                 'disable-notifications':
                                     self._disable_notifications_handler,
                                 'enable-notifications':
                                     self._enable_notifications_handler}

        self.cf_type_map = {'host': 'HOST', 'service': 'SVC'}
        self.fh = None

        # Type map of Nagios commands and their arguments/types, in
        # order, so an ordered command can be produced.
        self.nagios_commands = {
            'ACKNOWLEDGE_HOST_PROBLEM':
                [('host_name',           str,  ''),
                 ('sticky',              bool, True),
                 ('notify',              bool, True),
                 ('persistent',          bool, True),
                 ('author',              str,  'Unknown'),
                 ('comment',             str,  '')],
            'ACKNOWLEDGE_SVC_PROBLEM':
                [('host_name',           str, ''),
                 ('service_description', str, ''),
                 ('sticky',              bool, True),
                 ('notify',              bool, True),
                 ('persistent',          bool, True),
                 ('author',              str, 'Unknown'),
                 ('comment',             str, '')],
            'ADD_HOST_COMMENT':
                [('host_name',           str,  ''),
                 ('persistent',          bool, True),
                 ('author',              str,  ''),
                 ('comment',             str,  '')],
            'ADD_SVC_COMMENT':
                [('host_name',           str,  ''),
                 ('service_description', str,  ''),
                 ('persistent',          bool, True),
                 ('author',              str,  ''),
                 ('comment',             str,  '')],
            'DISABLE_HOST_NOTIFICATIONS':
                [('host_name',           str,  '')],
            'DISABLE_SVC_NOTIFICATIONS':
                [('host_name',           str,  ''),
                 ('service_description', str,  '')],
            'ENABLE_HOST_NOTIFICATIONS':
                [('host_name',           str,  '')],
            'ENABLE_SVC_NOTIFICATIONS':
                [('host_name',           str,  ''),
                 ('service_description', str,  '')],
        }

        super(NagiosCommandProcessor, self).__init__(config, event_data)

    def handle_command(self, command, data):
        """Dispatch a #command to the appropriate handler method.

        Before dispatching any command, we want to ensure that the
        command file is open.

        """
        self._open_command_file()

        super(NagiosCommandProcessor, self).handle_command(
                command, data)

    def _acknowledge_handler(self, opts, data):
        """Handle #acknowledge command.

        Acknowledge an alert on a host or service.

        """
        opts = dict(opts.items() + [('comment', data)])

        log.debug("Acknowledging alert")
        self._submit_command('ACKNOWLEDGE_{type}_PROBLEM', opts)

    def _comment_handler(self, opts, data):
        """Handle #comment command.

        Add a comment to a host or service definition.

        """
        opts = dict(opts.items() + [('comment', data)])

        log.debug("Adding comment")
        self._submit_command('ADD_{type}_COMMENT', opts)

    def _disable_notifications_handler(self, opts, data):
        """Handle #disable-notifications command.

        Disable notifications on a host or service.

        """
        log.debug("Disabling notifications")
        self._submit_command('DISABLE_{type}_NOTIFICATIONS', opts)

    def _enable_notifications_handler(self, opts, data):
        """Handle #enable-notifications command.

        Enable notifications on a host or service.

        """
        log.debug("Enabling notifications")
        self._submit_command('ENABLE_{type}_NOTIFICATIONS', opts)

    def _as_str(self, value):
        """Convert arguments to strings in the Nagios command format.

        The Nagios command format expects boolean values to be
        expressed as integers, rather than the string literals True
        or False. If value is a bool, return the string representation
        of its integer value. For all other types, return the string
        representation of value.

        """
        if type(value) == bool:
            return str(int(value))
        else:
            return str(value)

    def _build_command_line(self, command, opts):
        """Build a command line for the Nagios command file.

        Given a command and a list of options, cross-reference the
        command spec for the argument order and default values,
        then build a string suitable for insertion into the Nagios
        command file.

        """
        opt_spec = self.nagios_commands.get(command, [])
        keys = [key for (key, type_, default) in opt_spec]
        default_opts = dict([(key, default) for (key, type_, default)
                             in opt_spec])

        opts = dict(opts.items() + default_opts.items() + opts.items())

        arg_list = [command]
        for (key, type_, default) in opt_spec:
            arg_list.append(self._cast_arg(opts[key], type_))

        arg_list = [self._as_str(arg) for arg in arg_list]

        cmdline = ';'.join(arg_list)
        timestamp = int(time.time())
        return '[{timestamp}] {cmdline}'.format(cmdline=cmdline,
                                                timestamp=timestamp)

    def _cast_arg(self, value, type_):
        """Cast an input value to the type specified in the optspec.

        Boolean values can take many forms: 1, True, On, etc.
        Convert all of these strings to 
        """
        s = str(value)

        if type_ == bool:
            if re.match('(on|true|yes|1)$', s, re.IGNORECASE):
                return True
            elif re.match('off|false|no|0)$', s, re.IGNORECASE):
                return False
            else:
                fmt = 'Could not convert {value} to {type}'
                msg = fmt.format(type=type_, value=value)
                raise ValueError(msg)
        elif type_ == int:
            return int(s)
        elif type_ == str:
            return s
        else:
            # Fixme: Should throw exception
            return None

    def _cf_type(self):
        """Returns the event type in a Nagios-friendly format.

        The command file has two forms of many commands, such as
        ADD_HOST_COMMENT and ADD_SVC_COMMENT. These, rather predictably,
        function on hosts and services, respectively. This method
        converts the internal event data type name into one suitable
        for disambiguating Nagios commands.

        """
        if self.event_data['type'] == 'host':
            return 'HOST'
        elif self.event_data['type'] == 'service':
            return 'SVC'

    def _map_options(self, opts):
        """Remap program option names to Nagios API canonical names.

        Convert internal option keys to the key names used in the Nagios
        External Commands API:

        http://old.nagios.org/developerinfo/externalcommands/commandlist.php

        """
        map = {'hostname': 'host_name',
               'service': 'service_description'}

        new_opts = copy.copy(opts)
        for (old_key, new_key) in map.items():
            if old_key in new_opts:
                new_opts[new_key] = new_opts[old_key]
                del new_opts[old_key]

        return new_opts

    def _open_command_file(self):
        """Open the command file if it is not already open.
        """
        log.debug("Opening command file")

        # Todo: Handle IOError properly
        if self.fh is None:
            self.fh = open(self.config['command_file'], 'a')

    def _submit_command(self, command, opts):
        """Submit a command for processing.

        Takes a command and a dict of keyword arguments and converts
        them into a valid set of positional parameters, then writes
        it to the command file.

        """
        command = command.format(type=self._cf_type())
        args = dict(opts.items() + self.event_data.items())
        args = self._map_options(args)
        cmd_line = self._build_command_line(command, args)
        self._write_command_file(cmd_line)

    def _write_command_file(self, s):
        log.info("Writing to command file: " + s)
        self.fh.write(s + '\n')


def create_processors(config, event_data):
    """Create instances of Processors defined in configuration.
    """
    processors = []

    for class_name, class_config in config.items():
        try:
            if not class_config.as_bool('enable'):
                continue
        except (KeyError, ValueError) as ex:
            continue

        class_ = getattr(__main__, class_name)
        instance = class_(config=class_config, event_data=event_data)
        processors.append(instance)

    return processors


def extract_author_name(s):
    """Return the name portion of an RFC822 email address.

    Given a string parsed from an email's From: field, e.g.
    "Author <email@domain>", return only the author's name.
    Return the mailbox portion of the email address if no author
    name is supplied. Return the whole address if the email is not in
    username@domain format.

    """
    (real_name, address) = parseaddr(s)
    if real_name != '':
        return real_name
    elif real_name == '' and address == '':
        return 'Unknown Author'
    else:
        matches = re.match('([^@]+)@(.+)', address)
        if matches:
            return matches.group(1)
        else:
            return address


def extract_event_data(msg, config):
    """Parse event data from a Message object.
    """
    author = extract_author_name(msg.get('From', ''))
    subject = msg.get('Subject', '')
    alert = extract_alert(msg)
    reply = extract_reply(msg)

    parsed_fields = parse_alert_fields(alert, config['fields'])
    if parsed_fields['service'] is not None:
        type_ = 'service'
    else:
        type_ = 'host'

    if parsed_fields['timestamp'] == None:
        parsed_fields['timestamp'] = ''
    timestamp = parse_timestamp(parsed_fields['timestamp'],
                                config['date_format'])

    fields = {'alert': alert,
              'author': author,
              'message': msg.as_string(),
              'reply': reply,
              'timestamp': timestamp,
              'type': type_}

    return dict(parsed_fields.items() + fields.items())


def extract_alert(msg):
    """Extract the original alert from an email thread.

    Walk through all replies comprising the message, locate the
    original alert email, strip off all pseudo-headers, remove quote
    markers, and return the result.

    """
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            content = EmailReplyParser.read(
                    part.get_payload(decode=True))
            for fragment in content.fragments:
                content = fragment._content
                if content != extract_reply(msg):
                    return sanitize_email_fragment(content)

    return ''


def extract_reply(msg):
    """Extracts the portion of an email that should contain commands.
    """
    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            content = part.get_payload(decode=True)
            return EmailReplyParser.parse_reply(content)


def parse_alert_fields(s, config):
    """Parse named fields from an alert message.

    Given a list of key names and regular expressions in the config,
    attempt to extract all identified fields from the alert message
    and return them as a dict.

    """
    fields = {}
    flags = re.DOTALL | re.IGNORECASE | re.MULTILINE

    for (field, expr) in config.items():
        matches = re.search(expr, s, flags)
        if matches is not None:
            fields[field] = matches.group(1)
        else:
            fields[field] = None

    return fields


def parse_command(s):
    """Parse a command string from a reply email.

    Given a single-line command string, e.g.:
      #acknowlege Server owner notified of problem.

    return a tuple (command, data) consisting of the command name
    (acknowledge) and the remainder of the line. Argument parsing is
    delegated to Handler classes so that Handler authors can override
    option syntax if they so choose.

    """
    matches = re.match('#(\S+)(?:(?::\s*|\s+)(.+))?', s)
    if matches is not None:
        return (matches.group(1), matches.group(2))
    else:
        return (None, None)


def parse_timestamp(ts, format_name):
    """Attempt to parse the time from an alert email.

    Nagios has four configurable time formats, and uses none of them if
    the $LONGDATETIME$ macro is used in an alert (as it does by default)
    instead of the $DATETIME$ macro. 

    Parsing is attempted in the following order:

    - $LONGDATETIME$ format
    - Nagios configured date format (format_name)
    
    If the timestamp is unparsable, give up and return the current
    datetime instead. It's better than nothing.

    """
    long_date_formats = {'us': '%m/%d/%Y %H:%M:%S',
                         'euro': '%d/%m/%Y %H:%M:%S',
                         'iso8601': '%Y-%m-%d %H:%M:%S',
                         'strict-iso8601': '%Y-%M-%dT%H:%M:%S'}

    # Try parsing the date using the default Nagios $LONGDATETIME$
    # format. If that fails, attempt parsing using the $DATETIME$ format
    # specified in the configuration file. If that fails too, use
    # the current date and time (it's better than nothing).
    try:
        format_str = '%a %b %d %H:%M:%S %Z %Y'
        dt = datetime.datetime.strptime(ts, format_str)
    except ValueError, ex:
        try:
            format_str = long_date_formats[format_name]
            dt = datetime.datetime.strptime(ts, format_str)
        except ValueError, ex:
            dt = datetime.datetime.now()

    # Nagios and Icinga alert using the local timezone rather than UTC,
    # so we need to embed that information into our datetime.
    try:
        tz = get_localzone()
        return tz.localize(dt)
    except pytz.UnknownTimeZoneError, ex:
        return dt


def sanitize_email_fragment(s):
    """Remove pseudo-headers from message fragments in an email thread.

    EmailReplyParser returns fragments undisturbed, with inline heading
    (From:, To:, etc.) and quote markers (>) intact. This method removes
    these things and attempts to return the fragment to a pristine state
    (as much as possible).
    """
    expr = re.compile('^(--|On .+ at .+ wrote:|(?:\w+: .+)?$)')
    lines = s.split("\n")

    # Find the first line that doesn't look like a reply demarcation or
    # an inline heading, then return it and every line after it.
    for i in range(0, len(lines)):
        line = lines[i]
        if not expr.match(line):
            return "\n".join(map(strip_quote_marker, lines[i:-1]))

    return ''


def strip_quote_marker(s):
    """Strip out '>' quote markers in a quoted message fragment.
    """
    return re.sub('^(>\s*)+', '', s)


def validate_config(config):
    """Ensure that the application configuration is valid.
    """
    validator = Validator()
    result = config.validate(validator)

    if result != True:
        raise ConfigError(result.items())


def main():
    """Do the needful.
    """
    config = ConfigObj('/etc/koboli/koboli.ini',
                       configspec='/etc/koboli/kobolispec.ini',
                       list_values=True)

    try:
        validate_config(config)
    except ConfigError, ex: 
        # Fixme: better error reporting needed here
        log.critical("Config file validation failed; exiting.")
        sys.exit(1)

    msg = email.message_from_file(sys.stdin)

    # Set up the logging handler to respond
    from_addr = msg.get('To')
    to_addr = msg.get('From')
    subject = msg.get('Subject')
    if to_addr is not None:
        handler = BufferingSMTPHandler(mailhost='localhost',
                                       fromaddr=from_addr,
                                       toaddrs=to_addr,
                                       subject=subject)
        handler.setLevel(logging.INFO)
        log.addHandler(handler)

    try:
        event_data = extract_event_data(msg, config['global'])
        log.debug("Parsed event data: " + pformat(event_data))
    except EventDataError, ex:
        log.critical("Could not parse event data from email; exiting.")
        sys.exit(1)

    processors = create_processors(config, event_data)
    command_processors = {}
    for processor in processors:
        for command in processor.get_handled_commands():
            command_processors[command] = processor

    input_lines = event_data['reply'].split("\n")
    input_lines = [line for line in input_lines if line.strip() != '']
    commands = [parse_command(command) for command in input_lines]
    commands = [(command, data) for (command, data) in commands
                if command in command_processors]

    log.info("Processing commands...")
    for (command, data) in commands:
        command_processors[command].handle_command(command, data)
    log.info("Finished processing successfully.")


if __name__ == '__main__':
    log = logging.getLogger('log')
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)

    log.debug('Testing')

    try:
        main()
    except:
        log.error("Unhandled exception:\n{traceback}" \
                .format(traceback=traceback.format_exc()))
    finally:
        for handler in log.handlers:
            handler.flush()


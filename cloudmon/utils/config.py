# -*- coding: utf-8 -*-

"""This module contains functions and objects related to configuration
and data validation/treatment
"""

import os
import sys
import re
import io
import cerberus
import configobj

from schema import SCHEMA


class ConfigObjWithIncludes(configobj.ConfigObj):
    """This derived class is an extention to ConfigObj that adds nested
    includes to ini files.  Here's an example:

    db.ini:

        dbhostname=myserver
        dbname=some_database
        dbuser=dwight
        dbpassword=secrets

    app.ini:
        [source]
        +include ./db.ini

        [destination]
        +include ./db.ini

    when the 'app.ini' file is loaded, ConfigObj will respond as if the file
    had been written like this:
        [source]
        dbhostname=myserver
        dbname=some_database
        dbuser=dwight
        dbpassword=secrets

        [destination]
        dbhostname=myserver
        dbname=some_database
        dbuser=dwight
        dbpassword=secrets
    """
    _include_re = re.compile(r'^(\s*)\+include\s+(.*?)\s*$')

    def _substitute_env(self,file_name):
        """Reads filename, substitutes environment variables and returns a file-like
         object of the result.

        Substitution maps text like "$FOO" for the environment variable "FOO".
        """

        def lookup(match):
            """Replaces a match like $FOO with the env var FOO.
            """
            key = match.group(2)
            if key not in os.environ:
                raise Exception("Config env var '{}' not set".format(key)) # or ignore
            return os.environ.get(key)

        pattern = re.compile(r'(\s\$(\w+))')
        with open(file_name, 'r') as src:
            content = src.read()
            replaced = pattern.sub(lookup, content)

        try:
            return io.StringIO(unicode(replaced))
        except Exception, e:
            print replaced
            print "error: {}".format(e)
            sys.exit(1)

    def _expand_files(self, file_name, original_path, indent=""):
        """This recursive function accepts a file name, opens the file and then
        spools the contents of the file into a list, examining each line as it
        does so.  If it detects a line beginning with "+include", it assumes
        the string immediately following is a file name.  Recursing, the file
        new file is opened and its contents are spooled into the accumulating
        list."""
        expanded_file_contents = []
        with self._substitute_env(file_name) as f:
            for a_line in f:
                match = ConfigObjWithIncludes._include_re.match(a_line)
                if match:
                    include_file = match.group(2)
                    if include_file.startswith('.'):
                        include_file = os.path.join(
                            original_path,
                            include_file
                        )
                    new_lines = self._expand_files(include_file, os.path.dirname(include_file),
                                                   indent + match.group(1))
                    expanded_file_contents.extend(new_lines)
                else:
                    expanded_file_contents.append(indent + a_line.rstrip())
        return expanded_file_contents

    def _load(self, infile, configspec):
        """this overrides the original ConfigObj method of the same name.  It
        runs through the input file collecting lines into a list.  When
        completed, this method submits the list of lines to the super class'
        function of the same name.  ConfigObj proceeds, completely unaware
        that it's input file has been preprocessed."""
        if isinstance(infile, basestring):
            original_path = os.path.dirname(infile)
            expanded_file_contents = self._expand_files(infile, original_path)
            super(ConfigObjWithIncludes, self)._load(
                expanded_file_contents,
                configspec
            )
        else:
            super(ConfigObjWithIncludes, self)._load(infile, configspec)


class CustomValidator(cerberus.Validator):
    """"Customizations extending the Validator class"""

    def _validate_unique_dict_values(self, isunique, field, value):
        """ Test if the values of a dict are unique
        The rule's arguments are validated against this schema:
        {'type': 'boolean'}
        """
        if isunique:
            if not isinstance(value, dict):
                self._error(field, "Must be a dict")
        types = (dict, list, tuple, set)
        dict_vals = [i for i in value.itervalues() if not isinstance(i, types)]
        if len(dict_vals) != len(set(dict_vals)):
            self._error(field, "Can't have two or more equal values.")


def load_config(config_file):
    """Load, validate and treat the config file"""

    # load config file
    try:
        config = ConfigObjWithIncludes(
            config_file, file_error=True, list_values=False)
        raw_conf = config.dict()
    # rever exceptions
    except (IOError, configobj.ParseError) as error:
        sys.exit(error)

    # validate config file
    validator = CustomValidator(SCHEMA)
    if validator.validate(raw_conf):
        added_fields = diff_dict(validator.document, raw_conf)
        return validator.document, '\n'.join(flat_msgs(added_fields, '\t'))
    else:
        #raise SyntaxError('Validation failed!\n%s' % '\n'.join(flat_msgs(validator.errors)))
        errors = '\n'.join(flat_msgs(validator.errors))
        sys.exit('SyntaxError: Config Validation failed in {0}!\n{1}\n'.format(
            config_file, errors))


def flat_msgs(msgs, append='\tError in field '):
    """Expects a dict. Converts to string, flats  and formats it."""

    if isinstance(msgs, dict):
        for k, v in msgs.iteritems():
            if isinstance(v, dict):
                for d in flat_msgs(v, append + '['+ str(k) + ']'):
                    yield d
            elif isinstance(v, list) or isinstance(v, tuple):
                for i in v:
                    for d in flat_msgs(i, append + '['+ str(k) + ']'):
                        yield d
            else:
                yield append + '[' + str(k) + ']' + " - " + str(v)
    else:
        yield append + " - " + str(msgs)


def diff_dict(dict_a, dict_b):
    """"Simple diff between two dicts"""

    diff = list(set(dict_a.keys()) - set(dict_b.keys()))
    final = {i: dict_a[i] for i in diff if dict_a[i]}
    for k, v in dict_a.iteritems():
        if isinstance(v, dict) and dict_b.get(k):
            if isinstance(dict_b.get(k), dict):
                diff = list(set(v.keys()) - set(dict_b.get(k).keys()))
                if diff:
                    final[k] = {i: dict_a[k][i] for i in diff if dict_a[k][i]}
                    # Remove if empty else, proper format
                    if not final[k]:
                        del final[k]

    return final





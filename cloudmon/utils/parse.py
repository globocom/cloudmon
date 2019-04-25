
import re
import ast


# ConfigObj
def unquote(value):
    """Return an unquoted version of a string"""

    if isinstance(value, basestring):
        value = value.strip()
        if (value != '') and (value[0] == value[-1]) and (value[0] in ('"', "'")):
            value = value[1:-1]
        return value
    else:
        raise TypeError


def str_to_list(value, divider=',' ):
    """Given a value string, unquote, remove comment, handle lists.
    (including empty and single member lists)
    """

    if not value:
        return []
    value = value.strip()
    mat = value_divider(divider).match(value)
    if mat is None:
        # the value is badly constructed, probably badly quoted,
        # or an invalid list
        raise SyntaxError()
    (list_values, single, empty_list) = mat.groups()
    if (list_values == '') and (single is None):
        # change this if you want to accept empty values
        raise SyntaxError()
    # NOTE: note there is no error handling from here if the regex
    # is wrong: then incorrect values will slip through
    if empty_list is not None:
        # the single comma - meaning an empty list
        return []
    if single is not None:
        # handle empty values
        if list_values and not single:
            # fixme: the '' is a workaround because our regex now matches
            #   '' at the end of a list if it has a trailing comma
            single = None
        else:
            single = single or '""'
            single = unquote(single)
    if list_values == '':
        # not a list value
        return [single]
    the_list = listvalue_divider(divider).findall(list_values)
    the_list = [unquote(val) for val in the_list]
    if single is not None:
        the_list += [single]
    the_list = list(set(the_list))
    return the_list


def parse_bytes_suffix(value):
    """Converts a string cointaining a float number with a byte suffix
    (k, kb, ki, m, mb, mi, g, gb, gi, case insensitive) to the total
    int bytes amount (in base 10)
    """

    suffixes = {
        'k': 1024,
        'kb': 1024,
        'ki': 1024,
        'm': 1048576,
        'mb': 1048576,
        'mi': 1048576,
        'g': 1073741824,
        'gb': 1073741824,
        'gi': 1073741824,
    }

    if isinstance(value, basestring):
        value = unquote(value)
        value = value.strip().lower()
        if not value:
            return 0

        mat = re.match(r'^(\d*\.?\d+)\s*([kmg][bi]?)?$', value)
        if mat:
            (num, suf) = mat.groups()
            return int(float(num) * suffixes.get(suf, 1))
        else:
            raise SyntaxError(
                'Syntax error at %s\n'
                'Accepts a float number followed by a byte suffix '
                '(k, kb, ki, m, mb, mi, g, gb, gi, case insensitive)' % value
            )
    elif isinstance(value, (int, float, long)):
        return int(value)
    else:
        raise TypeError('%s must be string or numeric type' % value)


def to_bool(value):
    """Converts strings, ints or floats to bool. Empty strings
    are false
    """

    if isinstance(value, basestring):
        value = unquote(value)
        value = value.strip().lower()
        if value in ['true', 't', 'yes', 'y', '1']:
            return True
        elif value in ['false', 'f', 'no', 'n', '0', '']:
            return False
        else:
            raise NotImplementedError("Unknown bool %s" % value)
    elif isinstance(value, (int, float, bool)):
        return bool(value)
    return value

def parse_zabbix_macro(value, divider=','):
    value = value.strip()
    res = {}
    for macro_full in str_to_list(value, divider):
        if macro_full:
            macro_full = macro_full.strip()
            mat = RE_ZABBIX_MACRO.match(macro_full)
            if mat:
                (macro, macro_value) = mat.groups()
                res[macro] = {'macro': macro, 'value': macro_value}
                # res.append({'macro': macro, 'value': macro_value})
                # validar params
            else:
                raise SyntaxError('Syntax error at %s' % macro_full)
    return res.values()



def parse_zabbix_api(value, divider=';'):
    """Given a value string with one or multiple api calls,
    parse its parts
    """
    value = value.strip()
    res = []
    for api_call in str_to_list(value, divider):
        if api_call:
            api_call = api_call.strip()
            mat = RE_ZABBIX_API_SING.match(api_call)
            if mat:
                (api_class, api_method, params) = mat.groups()
                try:
                    if params:
                        params = ast.literal_eval(params)
                except Exception:  # tratar aqui
                    raise SyntaxError('Syntax error at %s' % params)
                res.append({'class': api_class, 'method': api_method, 'params': params})
                #validar params
            else:
                raise SyntaxError('Syntax error at %s' % api_call)
    return res

"""
Compiled Regular Expressions
"""

#^((\w+)\.(\w+)\s*\(\s*(\{.*\})\s*\)\s*;\s*)*((\w+)\.(\w+)\s*\(\s*(\{.*\})\s*\)\s*;?\s*)$
def value_divider(divider):
    re_value = re.compile(r'''^
        (?:
            (?:
                (
                    (?:
                        (?:
                            (?:".*?")|              # double quotes
                            (?:'.*?')|              # single quotes
                            (?:[^'"{0}\#][^{0}\#]*?)    # unquoted
                        )
                        \s*{0}\s*                     # divider
                    )*      # match all list items ending in a comma (if any)
                )
                (
                    (?:".*?")|                      # double quotes
                    (?:'.*?')|                      # single quotes
                    (?:[^'"{0}\#\s][^{0}]*?)|           # unquoted
                    (?:(?<!{0}))                      # Empty value
                )?          # last item in a list - or string value
            )|
            ({0})             # divider - empty list
        )
        $'''.format(divider), re.VERBOSE)
    return re_value

def listvalue_divider(divider):
    # use findall to get the members of a list value
    re_listvalue = re.compile(r'''
        (
            (?:".*?")|          # double quotes
            (?:'.*?')|          # single quotes
            (?:[^'"{0}\#]?.*?)    # unquoted
        )
        \s*{0}\s*                 # divider
        '''.format(divider), re.VERBOSE)
    return re_listvalue

def filter_blacklist(ini_list, names=[], regexs=[], logger=None):
    names_lo = [i.lower().strip() for i in names]
    regexs_comp = '|'.join(regexs)

    res = filter(lambda x: x.lower().strip() not in names_lo, ini_list)

    if regexs_comp:
        res = filter(lambda x: not re.search(regexs_comp, x), res)
    diff = list(set(ini_list) - set(res))
    if logger and diff:
        logger.debug(
            "The following entries are blacklisted and not gonna be send: %s"
            % diff
        )
    return (res, diff)


def list_monitoring_tags(tags_conf):
    """Parses CloudMon tag configuration and returns tags that represent
    a monitoring action
    """
    monitoring_tags = []
    for kind, values in tags_conf.iteritems():
        if kind == 'monitoring':
            monitoring_tags.append(values)
        elif kind == 'shortcuts':
            for custom_name, custom_values in values.iteritems():
                if int(custom_values.get('monitoring', 0)) == 1:
                    monitoring_tags.append(custom_name)
    return monitoring_tags

#ipv4re = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

# Not ideal with [^;]. Will not match if a parameter has a ';'
RE_ZABBIX_API_MULT = re.compile(r'''^
    (\w+ \. \w+ \s* \( \s* \{[^;]*\} \s* \) \s* ; \s*)*
    (\w+ \. \w+ \s* \( \s* \{[^;]*\} \s* \) \s* ;?)
    $''',
    re.VERBOSE)

# RE_ZABBIX_API_SING = re.compile(r'''^
#     (\w+)\.(\w+)\s*\(\s*(\{[^;]*\})\s*\)
#     $''',
#     re.VERBOSE)

RE_ZABBIX_API_SING = re.compile(r'''^
    (\w+)\.(\w+)\s*\(\s*(.*)\s*\)
    $''', re.VERBOSE)

RE_ZABBIX_MACRO = re.compile(r'''^
    ( \{ \$ [A-Z0-9_\.]+ (?:\:.+)? \} ) \s*\:\s* (.+)
    $''', re.VERBOSE)


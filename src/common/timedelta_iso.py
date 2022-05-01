# MIT No Attribution
#
# Copyright 2022 Ben Kehoe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""fromisoformat() and isoformat() functions for datetime.timedelta"""

__all__ = ["fromisoformat", "isoformat"]

from datetime import timedelta
import re

_NUMBER_PATTERN = r"([0-9]+)(.[0-9]{1,6})?"

PATTERN = re.compile(
    r"P" +
    # parse years and months for better error messages
    r"((?P<years>"  + _NUMBER_PATTERN + ")Y)?" +
    r"((?P<months>" + _NUMBER_PATTERN + ")M)?" +
    r"((?P<days>"   + _NUMBER_PATTERN + ")D)?" +
    r"(" +
        r"T" +
        r"((?P<hours>"   + _NUMBER_PATTERN + ")H)?" +
        r"((?P<minutes>" + _NUMBER_PATTERN + ")M)?" +
        r"((?P<seconds>" + _NUMBER_PATTERN + ")S)?" +
    r")?"
)

# Weeks are their own pattern
WEEK_PATTERN = re.compile(r"P(?P<weeks>[0-9]+)W")

def fromisoformat(s: str) -> timedelta:
    """Returns a timedelta for one of two ISO8601 duration formats:
    PnDTnHnMnS
    PnW

    timedelta does not support years or months.

    Additionally, timedelta's normalized representation may cause loss of
    fidelity. In ISO8601, P36H is distinct from P1DT12H and would result
    in different datetime when added to a datetime just before a DST boundary,
    but fromisoformat() will return the same timedelta value for both,
    representing 1 day and 43200 seconds.

    In keeping with the datetime module, support for formatting only extends
    as far as roundtripping from isoformat().
    """
    match = PATTERN.fullmatch(s)

    if not match:
        match = WEEK_PATTERN.fullmatch(s) # Assume week format is less likely
        if match:
            return timedelta(weeks=int(match.group("weeks")))

        raise ValueError("Not a valid or supported duration")

    if match.group("years") or match.group("months"):
        raise ValueError("timedelta does not support years or months")

    params = {}
    last_field = True
    for key in ["seconds", "minutes", "hours", "days"]:
        value = match.group(key)
        if value:
            if not last_field and "." in value:
                raise ValueError("Fractions are only allowed in the last field")
            params[key] = float(value)
            last_field = False

    return timedelta(**params)

def isoformat(td: timedelta) -> str:
    """Returns an ISO8601-formatted representation of the timedelta.

    Negative values are not supported by ISO8601.
    timedelta(0) is represented as 'PT0S'.
    If microseconds is not zero, fractional seconds are included at
    6 digits of precision using a period as the decimal separator,
    like other datetime objects.
    """
    if td.days < 0: # only days can be negative
        raise ValueError("ISO8601 does not support negative durations")

    if not td:
        return "PT0S"

    parts = ["P"]
    if td.days:
        parts.extend([str(td.days), "D"])

    if td.seconds:
        parts.append("T")

        seconds = td.seconds

        hours, seconds = divmod(seconds, 3600)
        if hours:
            parts.extend([str(hours), "H"])

        minutes, seconds = divmod(seconds, 60)
        if minutes:
            parts.extend([str(minutes), "M"])

        if seconds or td.microseconds:
            parts.append(str(seconds))
        if td.microseconds:
            parts.append(".{:06d}".format(td.microseconds))
        if seconds or td.microseconds:
            parts.append("S")

    return "".join(parts)
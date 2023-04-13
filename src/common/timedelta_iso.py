# Copyright 2022 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# original at https://gist.github.com/benkehoe/5b03c308b038b29e42106f602e554010

"""fromisoformat() and isoformat() functions for datetime.timedelta"""

__all__ = ["fromisoformat", "isoformat"]

from datetime import timedelta
import re

_NUMBER_PATTERN = r"([0-9]+)(.[0-9]{1,6})?"

PATTERN = re.compile(
    r"P"
    +
    # parse years and months for better error messages
    r"((?P<years>"
    + _NUMBER_PATTERN
    + ")Y)?"
    + r"((?P<months>"
    + _NUMBER_PATTERN
    + ")M)?"
    + r"((?P<days>"
    + _NUMBER_PATTERN
    + ")D)?"
    + r"("
    + r"T"
    + r"((?P<hours>"
    + _NUMBER_PATTERN
    + ")H)?"
    + r"((?P<minutes>"
    + _NUMBER_PATTERN
    + ")M)?"
    + r"((?P<seconds>"
    + _NUMBER_PATTERN
    + ")S)?"
    + r")?"
)

# Weeks are their own pattern
WEEK_PATTERN = re.compile(r"P(?P<weeks>[0-9]+)W")


def fromisoformat(s: str) -> timedelta:  # pylint: disable=C0103
    """Returns a timedelta for one of two ISO8601 duration formats:
    PnDTnHnMnS
    PnW

    timedelta does not support years or months.

    Additionally, timedelta's normalized representation may cause loss of
    fidelity. In ISO8601, PT36H is distinct from P1DT12H and would result
    in different datetime when added to a datetime just before a DST boundary,
    but fromisoformat() will return the same timedelta value for both,
    representing 1 day and 43200 seconds.

    In keeping with the datetime module, support for formatting only extends
    as far as roundtripping from isoformat().
    """
    # Must have at least one field
    if len(s) < 3:
        raise ValueError("Not a valid or supported duration")

    match = PATTERN.fullmatch(s)

    if not match:
        match = WEEK_PATTERN.fullmatch(s)  # Assume week format is less likely
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


def isoformat(td: timedelta) -> str:  # pylint: disable=C0103
    """Returns an ISO8601-formatted representation of the timedelta.

    Negative values are not supported by ISO8601.
    timedelta(0) is represented as 'PT0S'.
    If microseconds is not zero, fractional seconds are included at
    6 digits of precision using a period as the decimal separator,
    like other datetime objects.
    """
    if td.days < 0:  # other timedelta fields can't be negative, just check days
        raise ValueError("ISO8601 does not support negative durations")

    if not td:
        return "PT0S"

    s = "P"
    if td.days:
        s += str(td.days) + "D"

    if td.seconds or td.microseconds:
        s += "T"

        seconds = td.seconds

        hours, seconds = divmod(seconds, 3600)
        if hours:
            s += str(hours) + "H"

        minutes, seconds = divmod(seconds, 60)
        if minutes:
            s += str(minutes) + "M"

        if seconds or td.microseconds:
            s += str(seconds)
        if td.microseconds:
            s += ".{:06d}".format(td.microseconds)  # pylint: disable=C0209
        if seconds or td.microseconds:
            s += "S"

    return s

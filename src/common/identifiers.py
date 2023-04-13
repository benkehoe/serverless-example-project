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

import urllib.parse

"""
Composite key escaping
base32hex preserves ordering
trigraph separator: https://gist.github.com/benkehoe/4ab771a689c05ed64b122cdd96ed1b12
"""

# TODO: this is probably under-typed


def quote(s: str) -> str:
    return urllib.parse.quote_plus(s)


def unquote(s: str) -> str:
    return urllib.parse.unquote_plus(s)


def get_name_key(name: str) -> tuple[str, str]:
    pk = f"Name#{quote(name)}"
    sk = "__item__"
    return pk, sk


def _parse(s: str) -> tuple:
    return tuple(unquote(v) for v in s.split("#"))


def parse_key(pk: str, sk: str) -> tuple[tuple, tuple]:
    return _parse(pk), _parse(sk)

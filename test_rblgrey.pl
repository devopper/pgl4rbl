#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Copyright (c) 2014 Develer S.r.L
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

import StringIO
import sys

import MySQLdb
import pytest

import rblgrey

#
# Ugly hack to "configure" rblgrey
#

execfile("rblgrey.conf")
setattr(rblgrey, "CHECK_BAD_HELO", CHECK_BAD_HELO)
setattr(rblgrey, "MAX_GREYLIST_TIME", MAX_GREYLIST_TIME)
setattr(rblgrey, "MIN_GREYLIST_TIME", MIN_GREYLIST_TIME)
setattr(rblgrey, "RBLS", RBLS)
setattr(rblgrey, "GREYLIST_WHITELIST", GREYLIST_WHITELIST)

#
# Tests
#

EXPECT_OK = "action=ok Greylisting OK\n\n"
EXPECT_FAIL = "action=451 4.7.1 Greylisting in action, please try later.\n\n"


@pytest.mark.parametrize("triplet", [
    ( "89.97.188.34", "trinity.develer.com", EXPECT_OK),
    ( "8.8.8.8", "dns1.google.com", EXPECT_OK),
    ( "8.8.8.8", "google", EXPECT_FAIL),
    ( "89.97.188.34", "[ciao]", EXPECT_FAIL),
    ( "89.97.188.34", "[255.256.1024.12]", EXPECT_FAIL),
])
def test_helo(capsys, monkeypatch, tmpdir, triplet):
    # Prepare
    setattr(rblgrey, "GREYLIST_DB", str(tmpdir))

    client_address, helo_name, expected = triplet
    mock_data = "client_address=%s\nhelo_name=%s" % (client_address, helo_name)

    rblgrey.load_config_file("rblgrey.conf")
    monkeypatch.setattr('sys.stdin', StringIO.StringIO(mock_data))
    conn = rblgrey.Database(HOST, USER, PASSWORD, DB)
    # Test
    rblgrey.process_one(conn)

    # Assert
    assert capsys.readouterr()[0] == expected

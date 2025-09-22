# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Toshiba printer detection
#        as the array key and the regex to extract the type/model as the value.
#
# @note The array key might contain a pattern like e.g. (numbers incrementing
#       for multiple same URLs):
#
#       #--avoid-dup1--#
#
#       to be able to have different array keys for the same URL.
#       Make sure to strip such patterns away with ereg_replace
#       in the VT calling this function.
#
# @return An array as described in the function description.
#
function get_toshiba_detect_urls() {

  local_var toshiba_detect_urls;

  toshiba_detect_urls = make_array();

  # NOWRAP>Copier Model&nbsp</TD><TD CLASS="clsBTableElement">TOSHIBA e-STUDIO352&nbsp</TD>
  toshiba_detect_urls["/TopAccess/Device/Device.htm"] = ">Copier Model.*>TOSHIBA [^&]+";

  toshiba_detect_urls["/Device/Device.html"]          = 'id="DeviceCopierModel"';

  # <TITLE>TOSHIBA e-STUDIO306CS</TITLE>
  toshiba_detect_urls["/"]                            = "<title>TOSHIBA (e-STUDIO[^<]+)</title>";

  # nb: Some TopAccess printers do not reply to /Device/Device.html
  toshiba_detect_urls["/#--avoid-dup1--#"]            = "<!-- <title>TopAccess</title> -->";

  # PRN_TYPE="B-EX4T2";
  toshiba_detect_urls["/machine.js"]                  = 'PRN_TYPE="([^"]+)";';

  return toshiba_detect_urls;
}

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Ricoh printer detection
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
function get_ricoh_detect_urls() {

  local_var ricoh_detect_urls;

  ricoh_detect_urls = make_array();

  # class="modelName">SP C250DN</td>
  ricoh_detect_urls["/machinei.asp?Lang=en-us"]  = 'class="modelName">([^<]+)<';

  # /web/guest/fr/websys/webArch/mainFrame.cgi
  ricoh_detect_urls["/"]                         = "/web/guest/([a-z]{2})/websys/webArch/mainFrame.cgi";

  # <title>RICOH SP 230DNw</title>
  ricoh_detect_urls["/general/information.html"] = "<title>RICOH ([ A-Z0-9-]+)</title>";

  return ricoh_detect_urls;
}

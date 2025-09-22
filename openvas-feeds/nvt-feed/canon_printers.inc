# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Canon printer detection
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
function get_canon_detect_urls() {

  local_var canon_detect_urls;

  canon_detect_urls = make_array();

  # nowrap>Canon MX920 series</td>
  canon_detect_urls["/index.html"]                             = "nowrap>Canon ([A-Z0-9]+)";

  # id="EID" value="http://rs.ciggws.net/rd.cgi?FNC=RUI_EID2&amp;RES=3&amp;DEV=MB5100+series&amp;CNM_SEP=0&amp;mdl=MB5100+series
  canon_detect_urls["/index.html#--avoid-dup1--#"]             = 'id="EID" value=.*;mdl=([A-Z0-9]+)';

  # <title>User Authentication : iR-ADV C3530 : iR-ADV C3530</title>
  canon_detect_urls["/"]                                       = "<title>User Authentication : ([^<:]+)[:<]";

  # <title>Remote UI: Login: LBP6030w/6018w: LBP6030w/6018w</title>
  canon_detect_urls["/#--avoid-dup1--#"]                       = "<title>Remote UI: Login:[^:]+: ([^&<:]+)[:<]";

  # nb: The first group is actually the device name which sometimes can be different from the model
  # <span id="deviceName">MF8200C&nbsp;Series / MF8200C&nbsp;Series / </span>
  # <span id="deviceName">iR-ADV C3520  / iR-ADV C3520 /  </span>
  # <span id="deviceName">i-SENSYS X 1643P  / i-SENSYS X 1643P /  </span>
  # <span id="deviceName">imageRUNNER&nbsp;2204F / imageRUNNER 2204F / </span>
  # id="deviceName">sinri / LBP6240
  canon_detect_urls["/#--avoid-dup2--#"]                       = 'id="deviceName">[^/]+/ ((LBP|MF|iPR |i-SENSYS (X )?|iR-ADV |imageRUNNER )[^&/< ]+)[&/< ]';

  # <title>Default Authentication : W5736 : iR-ADV C5235</title>
  canon_detect_urls["/#--avoid-dup3--#"]                       = "<title>Default Authentication :[^:]+: ([^&<:]+)[:<]";

  # nb: First sequence after Login: is device given name, which usually is identical with model name, but not always
  # <title>Remote UI: Login: MF450 Series: MF450 Series</title>
  # <title>Remote UI: Login: Abrau MF440: MF440 Series</title>
  canon_detect_urls["/t_noacc.html"]                           = "<title>Remote UI: Login:[^:]+: ([^&<:]+)[:<]";

  # <td nowrap><font size="1">Product Name:</font></td> <td nowrap>imageRUNNER2530</td>
  canon_detect_urls["/_top.html"]                              = ">Product Name:</font></td>[^<]+<td nowrap>([^<]+)<";

  # <title>Canon iX6800 series Network Configuration
  canon_detect_urls["/netconf.html"]                           = "<title>Canon ([^ ]+)";

  # <th>Product Name:</th> <td>MF4500 Series</td>
  canon_detect_urls["/t_welcom.cgi?page=Language_name&lang=1"] = ">Product Name:</th>[^>]+>([^< ]+)[^<]+<";

  return canon_detect_urls;
}

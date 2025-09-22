# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Epson printer detection
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
function get_epson_detect_urls() {

  local_var epson_detect_urls;

  epson_detect_urls = make_array();

  # <span class="header">WF-2760 Series</span>
  epson_detect_urls["/PRESENTATION/HTML/TOP/INDEX.HTML"]                         = '<span class="header">([A-Z0-9-]+) Series</span>';

  # <div class='tvboxlarge'>Artisan 730</div>
  epson_detect_urls["/PRESENTATION/HTML/TOP/INDEX.HTML#--avoid-dup1--#"]         = "<div class='tvboxlarge'>([^<]+)</div>";

  # <span class="header">PX-1700F</span>
  epson_detect_urls["/PRESENTATION/HTML/TOP/INDEX.HTML#--avoid-dup2--#"]         = '<span class="header">([A-Z]+-[A-Z0-9]+)</span>';

  # Printer Model Name</td> <td height="16">AL-MX300</td></tr>
  epson_detect_urls["/iPrinterHome.cgi"]                                         = "Printer Model Name</td>[^>]+>\s*([^>]+)<";

  # <title>ET-16650 Series</title>
  epson_detect_urls["/PRESENTATION/ADVANCED/FORCE_PASSWORD/TOP?accsessmethod=0"] = "<title>([A-Z0-9-]+) Series</title>";

  # Model Name</B></TD> <TD width="60%">Epson Stylus Pro 9890&nbsp;</TD>
  epson_detect_urls["/Istatus.htm"]                                              = "Model Name</B></TD>\s*[^>]+>Epson ([^&<]+)";

  # <TD width="40%" bgcolor="#CCCCFF"><B>Model Name</B></TD>\n<TD width="60%">Stylus Pro 9900&nbsp;</TD>
  epson_detect_urls["/Istatus.htm#--avoid-dup1--#"]                              = "<B>Model Name</B></TD>\s*[^>]+>([^&<]+)";

  # <span id="modelnumbertext">SC-P20000 Series</span>
  epson_detect_urls["/statusframe.html"]                                         = '"modelnumbertext">([A-Z0-9-]+)( Series)?';

  return epson_detect_urls;
}

# @brief Checks if the given version passed via the 'version' parameter is less than the version
#        given via the 'test_version' parameter.
#
# @note Some Epson printers firmware (eg. SC printers) uses a uncommon versioning system that will not be correctly compared by the existing version check functions.
#       Eg. for SC-F7200, CO030G6 is older (lower) than CO011LA. It seems that the important parts for comparison are the last 2 or 3 characters from the version.
#
# @param version      The version to be tested.
# @param test_version The version to be tested against.
#
# @return TRUE if the version passed via the 'version' parameter is less than the version passed via
#         the 'test_version' parameter, FALSE otherwise.
#
function epson_version_is_less( version, test_version ) {

  local_var version, test_version;
  local_var icase, debug, a, b;

  icase = TRUE;
  debug = FALSE;
  if( ! version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#epson_version_is_less" );

  if( ! test_version )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#test_version#-#epson_version_is_less" );

  a = eregmatch( pattern:"^[A-Z]{1,2}[0-9]{3}([A-Z])([A-Z0-9])([a-z])?", string:version );
  b = eregmatch( pattern:"^[A-Z]{1,2}[0-9]{3}([A-Z])([A-Z0-9])([a-z])?", string:test_version );

  if ( ! isnull( a[1] ) && ! isnull( b[1] ) && ! isnull( a[2] ) && ! isnull( b[2] ) ) {
    if ( version_test( version:a[1], test_version:b[1], less:TRUE, icase:icase, debug:debug ) ) {
      return TRUE;
    } else if ( version_test( version:a[1], test_version:b[1], less:FALSE, icase:icase, debug:debug ) ) {
      if ( version_test( version:a[2], test_version:b[2], less:TRUE, icase:icase, debug:debug ) ) {
        return TRUE;
      } else if ( version_test( version:a[2], test_version:b[2], less:FALSE, icase:icase, debug:debug ) ) {
        if ( ! isnull( a[3] ) && ! isnull( b[3] ) ) {
          return ( version_test( version:a[3], test_version:b[3], less:TRUE, icase:icase, debug:debug ) );
        } else if ( ! isnull( b[3] ) ) {
          return TRUE;
        }
      }
    }
    # nb: All cases unchecked above reach here
    return FALSE;
  } else {
    # nb: Not the special case we are looking for, defaulting to standard version check
    return version_is_less( version:version, test_version:test_version );
  }
  # version_test( version:version, test_version:test_version, less:FALSE, icase:icase, debug:debug )
}

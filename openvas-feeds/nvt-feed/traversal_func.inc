# SPDX-License-Identifier: GPL-2.0-only
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-FileCopyrightText: 2025 Greenbone AG

# @brief Creates an array of common files to check during "Path traversal" attacks. The array contains the
#        the regex to match against the expected content of these files as the array key and the file to check
#        as the array value. The function will chose the returned files if the remote system is running on
#        Windows, Linux or if the OS is unknown.
#
# @param _FCT_ANON_ARGS[0] Allows (optional) to pass either "windows" or "linux" as an anonymous function parameter
#                          to define directly which kind of files should be returned.
#
# @note Add a dependency to os_detection.nasl if you want to use this function. The VT calling this
#       function needs to also include os_func.inc (for @ref os_host_runs()).
#
# @note A caller should use a case insensitive response check for the regex below (e.g.
#       "egrep(*snip*icase:TRUE)" or "=~" due to the "supporT" string for Windows systems used below
#       (see relevant comment below for more info).
#
# @return An array as described in the function summary.
#
function traversal_files() {

  local_var res;

  if( _FCT_ANON_ARGS[0] ) {

    if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ) {
      res = "yes";
    } else if( tolower( _FCT_ANON_ARGS[0] ) == "linux" ) {
      res = "no";
    }
  } else {
    res = os_host_runs( "windows" );
  }

  if( res == "yes" ) {
    return make_array( "\[boot loader\]", "boot.ini",
                       # nb: "supporT" is used here because NASL doesn't (at least currently) allows
                       # to have multiple same array keys with different values.
                       "; for 16-bit app supporT", "winnt/win.ini",
                       "; for 16-bit app support", "windows/win.ini" );
  } else if( res == "no" ) {
    # TBD: Also check e.g. etc/hosts for basic IDS?
    # nb:
    # - At least on a QNAP NAS no "root" account exists, hence "admin" and "nobody" is checked as well
    # - Historically, the user "nobody" was assigned UID -2 by several operating systems
    # - CVE-2024-20767 returns the content of the file in reverse order (root as the last entry on
    #   Linux systems). As we never know if this is happening for other flaws where the response
    #   might be even truncated (means no "root" included) additional well known accounts from Linux
    #   and Mac OS X systems are included as well. The Mac OS X ones have been taken from here:
    #   - https://vulners.com/zdt/1337DAY-ID-37968
    #   - https://ma4ter.oss-cn-beijing.aliyuncs.com/typecho/2024/03/18/1710767606.png (From https://jeva.cc/2973.html)
    return make_array( "(root|admin|nobody|_apt|www-data|_avphidbridge|_darwindaemon|_launchservices|_backgroundassets):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}", "etc/passwd" );
  }

  # nb:
  # - "unknown" operating system so checking all variants
  # - see the note on the different account names above
  # - see the note on the "supporT" above
  return make_array( "(root|admin|nobody|_apt|www-data|_avphidbridge|_darwindaemon|_launchservices|_backgroundassets):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}", "etc/passwd",
                     "\[boot loader\]", "boot.ini",
                     "; for 16-bit app supporT", "winnt/win.ini",
                     "; for 16-bit app support", "windows/win.ini" );
}

# @brief Creates a list of known default directory traversal pattern including variants with e.g.
#        different encoding.
#
# @param extra_pattern_list A list of additional pattern to be added to the internal default list.
# @param depth              The depth to traverse back. Defaults to 6 if not given.
#
# @note Explanation for some of the pattern can be found at e.g.
#       - https://web.archive.org/web/20170713175925/https://www.sans.org/security-resources/idfaq/what-are-unicode-vulnerabilities-on-internet-information-server-iis/9/15
#       - https://security.stackexchange.com/questions/48879/why-does-directory-traversal-attack-c0af-work
#       - https://owasp.org/www-community/attacks/Path_Traversal
#
# @note Most of the pattern should run against all OS variants (e.g. .\ and the like). A few special
#       like e.g. "C:../" are only Windows specific and are only running against such systems. If a
#       similar pattern for a drive letter is added please make sure to also add it to the relevant
#       check in the following VTs due to possible duplicated "prefix" handling:
#       - 2017/gb_generic_http_web_app_params_dir_trav.nasl
#       - 2017/gb_generic_http_web_root_dir_trav.nasl
#       - 2021/gb_generic_http_web_dirs_dir_trav.nasl
#
# @return A list of default traversal pattern.
#
function traversal_pattern( extra_pattern_list, depth ) {

  local_var extra_pattern_list, depth;
  local_var rounded_up_depth, traversal_pattern;

  if( ! depth )
    depth = 6;

  # A few cases below requires / should have an even number so just round up...
  rounded_up_depth = depth;
  if( rounded_up_depth % 2 )
    rounded_up_depth++;

  traversal_pattern = make_list(

    # <--- Forward slash cases start

    # The following three are for absolute traversal like e.g. //etc/passwd. For these the "depth" is ignored.
    "/",
    "//",
    "///",

    crap( data:"./", length:2 * depth ),
    crap( data:"../", length:3 * depth ),
    crap( data:".../", length:4 * depth ),
    crap( data:"....//", length:6 * depth ),
    crap( data:".....//", length:7 * depth ),
    crap( data:"%20../", length:6 * depth ),
    crap( data:"%u0020../", length:9 * depth ),
    crap( data:"%20.../", length:7 * depth ),
    crap( data:"%u0020.../", length:10 * depth ),
    crap( data:"%2e%2e%2f", length:9 * depth ),
    crap( data:"%u002e%u002e%u002f", length:18 * depth ),
    crap( data:"%2e%2e/", length:7 * depth ),
    crap( data:"%u002e%u002e/", length:13 * depth ),
    crap( data:"%2e./", length:5 * depth ),
    crap( data:"%u002e./", length:8 * depth ),
    crap( data:"..%2f", length:5 * depth ),
    crap( data:"..%u002f", length:8 * depth ),
    crap( data:"..%255f", length:7 * depth ),
    crap( data:"%252e%252e%255f", length:15 * depth ),
    crap( data:".%252e/", length:7 * depth ),

    # nb: JVM UTF-8 bug for various products, see e.g. 2011/gb_trend_micro_data_loss_prevention_48225.nasl or 2018/apache/gb_apache_tomcat_30633.nasl
    crap( data:"%c0%ae%c0%ae/", length:13 * depth ),

    # nb: Length calculation is a special case
    crap( data:"..///////..////..//////", length:23 * ( rounded_up_depth / 2 ) ),

    # nb: Special case to start with a trailing slash and a following backslash (%5C = \)
    "/" + crap( data:"%5C../", length:6 * depth ),

    # nb: As seen in CVE-2021-41773 but other environments / technologies might be affected as well
    ".%2e/" + crap( data:"%2e%2e/", length:7 * depth ),

    # nb: As seen in CVE-2021-42013 but other environments / technologies might be affected as well
    crap( data:".%%32%65/", length:9 * depth ),

   # nb: Also seen mentioned for CVE-2021-42013 but other environments / technologies might be affected as well
    crap( data:"%%32%65%%32%65/", length:15 * depth ),

   # nb: PHP < 5 but other environments / technologies might be affected as well
    crap( data:".%00.../", length:8 * depth ),

    # As seen in CVE-2017-14849 but other environments / technologies might be affected as well
    crap( data:"../", length:3 * ( rounded_up_depth / 2 ) ) + "a/" + crap( data:"../", length:3 * ( rounded_up_depth / 2 ) ),

    # nb: From e.g. https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
    crap( data:"..;/", length:4 * depth ),

    # nb: From e.g. https://octagon.net/blog/2022/01/22/cve-2021-45467-cwp-centos-web-panel-preauth-rce/
    crap( data:".%00./", length:6 * depth ),

    # nb: Link mentioned above mentions this bypass possibility
    crap( data:".%00%00./", length:9 * depth ),

    # Forward slash cases end --->

    # <--- Backward slash cases start

    # The following three are for absolute traversal like e.g. \\etc/passwd. For these the "depth" is ignored.
    "\",
    "\\",
    "\\\",

    crap( data:".\", length:2 * depth ),
    crap( data:"..\", length:3 * depth ),
    crap( data:"...\", length:4 * depth ),
    crap( data:"....\\", length:6 * depth ),
    crap( data:".....\\", length:7 * depth ),
    crap( data:"%20..\", length:6 * depth ),
    crap( data:"%u0020..\", length:9 * depth ),
    crap( data:"%20...\", length:7 * depth ),
    crap( data:"%u0020...\", length:10 * depth ),
    crap( data:"%2e%2e%5c", length:9 * depth ),
    crap( data:"%u002e%u002e%u005c", length:18 * depth ),
    crap( data:"%2e%2e\", length:7 * depth ),
    crap( data:"%u002e%u002e\", length:13 * depth ),
    crap( data:"%2e.\", length:5 * depth ),
    crap( data:"%u002e.\", length:8 * depth ),
    crap( data:"..%5c", length:5 * depth ),
    crap( data:"..%u005c", length:8 * depth ),
    crap( data:"..%255c", length:7 * depth ),
    crap( data:"%252e%252e%255c", length:15 * depth ),
    crap( data:".%252e\", length:7 * depth ),
    crap( data:"%c0%ae%c0%ae\", length:13 * depth ),

    # nb: Length calculation is a special case
    crap( data:"..\\\\\\\..\\\\..\\\\\\", length:23 * ( rounded_up_depth / 2 ) ),

    # nb: Special case to start with a trailing backslash and a follow up slash (%2F = /)
    "\" + crap( data:"%2F..\", length:6 * depth ),

    # nb: Backward slash case for CVE-2021-41773 but other environments / technologies might be affected as well
    ".%2e\" + crap( data:"%2e%2e\", length:7 * depth ),

    # nb: Backward slash case for CVE-2021-42013 but other environments / technologies might be affected as well
    crap( data:".%%32%65\", length:9 * depth ),

    # nb: Another backward slash case for CVE-2021-42013 but other environments / technologies might be affected as well
    crap( data:"%%32%65%%32%65\", length:15 * depth ),

    # nb: PHP < 5 but other environments / technologies might be affected as well
    crap( data:".%00...\", length:8 * depth ),

    # See CVE-2017-14849 case above, just using backward slash for possible increased coverage
    crap( data:"..\", length:3 * ( rounded_up_depth / 2 ) ) + "a\" + crap( data:"..\", length:3 * ( rounded_up_depth / 2 ) ),

    crap( data:"..;\", length:4 * depth ),
    crap( data:".%00.\", length:6 * depth ),
    crap( data:".%00%00.\", length:9 * depth ),

    # Backward slash cases end --->

    # Few additional special cases with mixed forward / backward slash cases
    crap( data:"..\../", length:6 * depth ),
    crap( data:"../..\", length:6 * depth ),
    crap( data:".\\./", length:5 * depth ),
    crap( data:".//.\", length:5 * depth ),
    crap( data:"..%c0%af../", length:11 * depth ),
    crap( data:"..%c0%af..\", length:11 * depth ),
    crap( data:"..%c1%9c../", length:11 * depth ),
    crap( data:"..%c1%9c..\", length:11 * depth ),

    # Additional special cases with only one slash variant

    # From https://github.com/cabraviva/path-sanitizer/security/advisories/GHSA-94p5-r7cc-3rpr
    crap( data:"..=%5c", length:6 * depth )
  );

  # nb: This one only makes sense:
  # - if we know that the target host is a Windows system OR
  # - it is unknown
  if( ( os_host_runs( "Windows" ) == "yes" ) ||
      ( os_host_runs( "Windows" ) == "unknown" ) ) {

    traversal_pattern = make_list(
      traversal_pattern,

      # This is for Splunk on Windows -> https://github.com/Mr-xn/CVE-2024-36991
      crap( data:"C:../", length:5 * depth )
    );
  }

  if( extra_pattern_list && ! is_array( extra_pattern_list ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#traversal_pattern(): No list passed in 'extra_pattern_list' parameter" );
  } else {
    traversal_pattern = make_list_unique( traversal_pattern, extra_pattern_list );
  }

  return traversal_pattern;
}

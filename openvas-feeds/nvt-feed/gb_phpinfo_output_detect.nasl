# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108474");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-10-19 13:33:54 +0200 (Fri, 19 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("phpinfo() Output Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  # nb: Don't add a dependency to "gb_php_http_detect.nasl" as this would cause a dependency cycle
  # because that VT has a dependency to this one.
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.php.net/manual/en/function.phpinfo.php");

  script_tag(name:"summary", value:"HTTP based detection of files containing the output of the
  phpinfo() PHP function.");

  script_tag(name:"vuldetect", value:"This script tries to identify known files containing an output
  of the phpinfo() PHP function. It will also evaluate previously detected files found by the VT
  'Web mirroring' (OID: 1.3.6.1.4.1.25623.1.0.10662).

  Note: The reporting takes place in a separate VT 'phpinfo() Output Reporting (HTTP)' (OID:
  1.3.6.1.4.1.25623.1.0.11229).");

  script_tag(name:"insight", value:"Many PHP installation tutorials instruct the user to create a
  file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often left
  back in the webserver directory.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file
  includes:

  The username of the user running the PHP process, if it is a sudo user, the IP address of the
  host, the web server version, the system version (Unix, Linux, Windows, ...), and the root
  directory of the web server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

global_var curr_phpinfo_list;
curr_phpinfo_list = make_list();

# nb:
# - Just some additional basic debug logging (can be still extended in the future if required)
# - Setting this to "1" is only enabling the logging of "skipped" URLs
# - Setting this to "2" is enabling logging of the previous and all checked URLs
DEBUG = 0;

function check_and_set_phpinfo( url, host, port ) {

  # nb: curr_phpinfo_list is globally passed into this function
  local_var url, host, port;
  local_var res, concl, vers;

  # nb: Shouldn't happen but checking it anyway
  if( ! url ) {
    if( DEBUG > 0 ) display( "DEBUG: Empty URL parameter passed to check_and_set_phpinfo() function" );
    return;
  }

  if( DEBUG > 1 ) display( "DEBUG: Testing '" + url + "' URL." );

  if( ! res = http_get_cache( item:url, port:port ) )
    return;

  if( ( res =~ "^HTTP/1\.[01] 200" ) && ( concl = http_check_for_phpinfo_output( data:res ) ) ) {

    curr_phpinfo_list = make_list( curr_phpinfo_list, url );

    set_kb_item( name:"php/phpinfo/detected", value:TRUE );
    set_kb_item( name:"php/phpinfo/http/detected", value:TRUE );
    set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected", value:TRUE );
    set_kb_item( name:"php/phpinfo/" + host + "/" + port + "/detected_urls", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/content/phpinfo_script/plain", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/content/phpinfo_script/reporting", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\nConcluded from:\n' + concl );

    # <h1 class="p">PHP Version 7.0.30-0+deb9u1</h1>
    # <h1 class="p">PHP Version 7.4.3-4ubuntu2.18</h1>
    # <h1 class="p">PHP Version 7.2.34</h1>
    #
    # but also e.g. these later on the page:
    #
    # <tr><td class="e">PHP Version </td><td class="v">7.4.3-4ubuntu2.18 </td></tr>
    # <tr><td class="e">PHP Version </td><td class="v">7.2.34 </td></tr>
    #
    vers = eregmatch( pattern:">PHP Version ([.0-9A-Za-z]+).*<", string:res );
    if( ! isnull( vers[1] ) ) {
      # nb: For later use/evaluation in gb_php_detect.nasl in the case no PHP or its version was detected from the banner
      set_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/urls", value:url );
      replace_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/short_versions/" + url, value:vers[1] );
      vers = eregmatch( pattern:">PHP Version ([^<]+)<", string:res );
      if( ! isnull( vers[1] ) )
        replace_kb_item( name:"php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + url, value:vers[1] );
    }
  }
  return;
}

# nb:
# - Note / important: When adding additional entries here including a sub-directory please make sure
#   to check / handle the exclusions similar to the other entries in the "foreach file" code below
# - CVE-2023-49103 isn't included here on purpose as it is already checked separately with a
#   dedicated/specific ownCloud active check
#
files = make_list(

  # Some common ones
  "/phpinfo.php",
  "/info.php",
  "/test.php",
  "/php_info.php",
  "/index.php",
  "/i.php",
  "/test.php?mode=phpinfo",

  # Seen on https://perishablepress.com/htaccess-secure-phpinfo-php/
  "/php-info.php",

  # Seen on various sources like e.g. https://github.com/jafrax/sppd/blob/master/infophp.php
  "/infophp.php",

  # Seen on various discussion forums / blog posts / tutorials
  "/infos.php",

  # CVE-2023-49282
  "/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php",

  # CVE-2023-49283
  "/vendor/microsoft/microsoft-graph-core/tests/GetPhpInfo.php",

  # CVE-2008-0149 for TUTOS
  "/php/admin/phpinfo.php",

  # Symfony profiler (debug mode)
  # see e.g. https://rahadchowdhury.medium.com/how-to-find-multiple-vulnerabilities-in-symfony-profiler-debug-mode-ccf2c5c7bb9f
  #
  # nb: While the article above shows / mentions some login these might be still accessible in some
  # special environments and thus have been added here
  "/_profiler/phpinfo",
  "/app_dev.php/_profiler/phpinfo",

  # CVE-2024-10486 for "Google for WooCommerce" WordPress plugin
  "/wp-content/plugins/google-listings-and-ads/vendor/googleads/google-ads-php/scripts/print_php_information.php",

  # From / used by https://github.com/gaodongyuan/php/blob/master/l.php
  "/l.php?act=phpinfo",

  # Those have been seen on various online tutorials/resources like e.g.:
  # - https://www.spaceship.com/knowledgebase/configure-php-settings-spaceship-shared-hosting/
  # - https://the.hosting/en/help/find-out-the-version-of-php
  # - https://moodle.org/mod/forum/discuss.php?d=450906
  # - https://stackoverflow.com/questions/6165558/how-can-i-find-my-php-ini-on-wordpress
  # - https://quantixed.org/2021/06/08/tips-from-the-blog-xv-locating-the-php-ini-file-for-wordpress-on-raspberry-pi/
  # - https://stackoverflow.com/a/56371201
  # - https://stackoverflow.com/questions/68272334/stomp-php-is-not-visible-in-xampp-http-localhost-dashboard-phpinfo-php
  # - https://www.luszcz.de/widwsisw/i/i0004en.php
  "/testinfo.php",
  "/phpversion.php",
  "/pinfo.php",
  "/asdf.php",
  "/?phpinfo=1",
  "/?phpinfo=-1",
  "/dashboard/phpinfo.php",
  "/linusadmin-phpinfo.php",
  "/_profiler/phpinfo.php",
  "/app_dev.php/_profiler/phpinfo.php"
);

port = http_get_port( default:80 );
# nb: Don't use http_can_host_php() here as this VT is reporting PHP as well and http_can_host_php()
# could fail if no PHP was detected before...

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( files ) {

    url = dir + file;

    # nb: Prevent some duplicated unnecessary checks like e.g.:
    # /dashboard/dashboard/phpinfo.php
    # if the "/dashboard" dir was already detected by the dir scanner...
    if( ( dir == "/vendor/microsoft/microsoft-graph/tests" && file == "/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php" ) ||
        ( dir == "/vendor/microsoft/microsoft-graph-core/tests" && file == "/vendor/microsoft/microsoft-graph-core/tests/GetPhpInfo.php" ) ||
        ( dir == "/php/admin" && file == "/php/admin/phpinfo.php" ) ||
        ( dir == "/_profiler" && file == "/_profiler/phpinfo" ) ||
        ( dir == "/app_dev.php/_profiler" && file == "/app_dev.php/_profiler/phpinfo" ) ||
        ( dir == "/wp-content/plugins/google-listings-and-ads/vendor/googleads/google-ads-php/scripts" && file == "/wp-content/plugins/google-listings-and-ads/vendor/googleads/google-ads-php/scripts/print_php_information.php" ) ||
        ( dir == "/dashboard" && file == "/dashboard/phpinfo.php" ) ||
        ( dir == "/_profiler" && file == "/_profiler/phpinfo.php" ) ||
        ( dir == "/app_dev.php/_profiler" && file == "/app_dev.php/_profiler/phpinfo.php" )
      ) {

      if( DEBUG >= 1 ) display( "DEBUG: Skipping '" + url + "' URL due to a duplicated '" + dir + "' folder." );
      continue;
    }

    check_and_set_phpinfo( url:url, host:host, port:port );
  }
}

# nb: This is filled by webmirror.nasl, the code here makes sure that we're not reporting the same
# script twice...
kb_phpinfo_scripts = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/plain" );

if( kb_phpinfo_scripts && is_array( kb_phpinfo_scripts ) ) {
  foreach kb_phpinfo_script( kb_phpinfo_scripts ) {
    if( curr_phpinfo_list && is_array( curr_phpinfo_list ) && ! in_array( search:kb_phpinfo_script, array:curr_phpinfo_list, part_match:FALSE ) ) {
      check_and_set_phpinfo( url:kb_phpinfo_script, host:host, port:port );
    }
  }
}

exit( 0 );

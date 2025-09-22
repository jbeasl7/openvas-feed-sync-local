# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103253");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-3500", "CVE-2011-3501");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cogent DataHub Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"summary", value:"Cogent DataHub is prone to a directory traversal vulnerability,
  an information disclosure vulnerability and to multiple buffer-overflow and integer-overflow
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting the issues may allow an attacker to obtain sensitive
  information that could aid in further attacks or may allow attackers to execute arbitrary code
  within the context of the privileged domain.");

  script_tag(name:"affected", value:"Cogent DataHub version 7.1.1.63 and probably prior.");

  script_tag(name:"solution", value:"Update to version 6.4.20, 7.1.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49610");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49611");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

files = traversal_files( "windows" );

foreach file( keys( files ) ) {

  url = "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

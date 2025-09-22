# SPDX-FileCopyrightText: 2001 StrongHoldNet
# SPDX-FileCopyrightText: 2001 Vincent Renardias
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10711");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2001-1010");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Sambar pagecount Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2001 Vincent Renardias & Copyright (C) 2001 StrongHoldNet");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"solution", value:"Remove this script.");

  script_tag(name:"summary", value:"By default, there is a pagecount script with Sambar Web Server
  located at http://sambarserver/session/pagecount.

  This counter writes its temporary files in c:\sambardirectory\tmp. It allows to overwrite any
  files on the filesystem since the 'page' parameter is not checked against '../../' attacks.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/199410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3092");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/session/pagecount";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res !~ "^HTTP/1\.[01] 404" ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

# SPDX-FileCopyrightText: 2005 SensePost
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18650");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-2086");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sambar <= 6.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 SensePost");
  script_family("Denial of Service");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"Sambar contains a flaw that may allow an attacker to crash the
  service remotely.

  A buffer overflow was found in the /search/results.stm application that comes shipped with Sambar
  Server.");

  script_tag(name:"affected", value:"Sambar Server version 4.x, 5.x and 6.0.");

  script_tag(name:"solution", value:"Update to a current release of this software.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9607");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/search/results.stm";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if(!res)
  exit( 0 );

if( egrep( pattern:"^Server: SAMBAR (4\.|5\.[01])", string:res, icase:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
} else if( egrep( pattern:"&copy; 1997-(199[8-9]|200[0-3]) Sambar Technologies, Inc. All rights reserved.",
                  string:res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

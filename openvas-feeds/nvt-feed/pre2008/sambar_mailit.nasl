# SPDX-FileCopyrightText: 2000 Hendrik Scholz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10417");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Sambar /cgi-bin/mailit.pl Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"The Sambar 'mailit.pl' CGI takes a POST request from any host
  and sends a mail to a supplied address.");

  script_tag(name:"vuldetect", value:"Checks if the mailit.pl CGI is installed.");

  script_tag(name:"solution", value:"Remove the CGI script from /cgi-bin.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/cgi-bin/mailit.pl";

if( http_is_cgi_installed_ka( item:url, port:port ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

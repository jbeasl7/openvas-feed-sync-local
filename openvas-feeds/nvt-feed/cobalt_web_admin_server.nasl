# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10793");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cobalt Web Administration Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the Cobalt Administration web server if
  you do not use it, or block inbound connections to this port.");

  script_tag(name:"summary", value:"The remote web server is the Cobalt Administration web server.");

  script_tag(name:"impact", value:"This web server enables attackers to configure your Cobalt server
  if they gain access to a valid authentication username and password.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:81 );

url = "/admin";
res = http_get_cache( item:url, port:port );

if( res =~ "^HTTP/1\.[01] 401" && ( ( "CobaltServer" >< res ) || ( "CobaltRQ" >< res ) ) && ( "WWW-Authenticate: Basic realm=" >< res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  log_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );

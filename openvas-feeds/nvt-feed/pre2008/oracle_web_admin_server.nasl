# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10738");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Oracle Web Administration Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable the Oracle Administration web server if it is unnecessary,
  or block the web server's port number on your Firewall.");

  script_tag(name:"summary", value:"We detected the remote web server as an Oracle
  Administration web server. This web server enables attackers to configure
  your Oracle Database server if they gain access to a valid authentication
  username and password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8888 );

buf = http_get_cache( item:"/", port:port );

if( "401 Unauthorized" >< buf && "Oracle_Web_Listener" >< buf && "WWW-Authenticate: Basic Realm=" >< buf ) {
  report = http_report_vuln_url( port:port, url:"/" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

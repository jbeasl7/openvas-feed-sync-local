# SPDX-FileCopyrightText: 2005 H. Scholz & Contributors
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10107");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 H. Scholz & Contributors");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Show full HTTP headers in output", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"This script detects and reports the HTTP Server's banner
  which might provide the type and version of it.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

show_headers = script_get_preference( "Show full HTTP headers in output", id:1 );
report = 'The remote HTTP Server banner is:\n\n';

port = http_get_port( default:80 );
headers = http_get_remote_headers( port:port, ignore_broken:TRUE );
if( ! headers || headers !~ "^HTTP/(0\.9|1\.[01]|2) +[0-9]{3}" )
  exit( 0 );

serverbanner = egrep( pattern:"^(DAAP-)?Server\s*:", string:headers, icase:TRUE );
if( ! serverbanner )
  exit( 0 );

serverbanner = chomp( serverbanner );
report += serverbanner;

if( show_headers == "yes" )
  report += '\n\nFull HTTP headers:\n\n' + headers;

log_message( port:port, data:report );

exit( 0 );

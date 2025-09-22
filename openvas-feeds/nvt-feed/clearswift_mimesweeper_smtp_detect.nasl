# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18219");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Clearswift MIMEsweeper Manager Console Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host appears to be running MIMEsweeper for SMTP, connections are
  allowed to the web MIMEsweeper manager console.");

  script_tag(name:"impact", value:"Letting attackers know that you are using this software will help them to focus
  their attack or will make them change their strategy.");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

url = "/MSWSMTP/Common/Authentication/Logon.aspx";

res = http_get_cache( item:url, port:port );
if( !res )
  exit( 0 );

if( "MIMEsweeper Manager" >< res && "infoTimeout_persistant" >< res ) {
  log_message( port:port );
}

exit( 0 );

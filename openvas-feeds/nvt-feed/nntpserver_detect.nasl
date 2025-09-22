# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10159");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("News Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service2.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/nntp", 119);

  script_tag(name:"summary", value:"This detects the News Server's type and version by connecting to the server
  and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("nntp_func.inc");
include("port_service_func.inc");

port = nntp_get_port( default:119 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

res = recv_line( socket:soc, length:1024 );
close( soc );
if( ! res || ( res !~ "^20[01] .*(NNTP|NNRP)" && res !~ "^100 .*commands" ) )
  exit( 0 );

res = chomp( res );

set_kb_item( name:"nntp/detected", value:TRUE );
replace_kb_item( name:"nntp/banner/" + port, value:res );

service_register( port:port, ipproto:"tcp", proto:"nntp" );
log_message( port:port, data:"Remote NNTP server banner : " + res );

exit( 0 );

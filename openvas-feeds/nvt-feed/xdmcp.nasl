# SPDX-FileCopyrightText: 2005 Pasi Eronen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10891");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("X Display Manager Control Protocol (XDMCP) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Pasi Eronen");
  script_family("Service detection");
  script_require_udp_ports(177);

  script_tag(name:"solution", value:"XDMCP should either be disabled or limited in the machines which
  may access the service.");

  script_tag(name:"summary", value:"The XDMCP service is running on the remote host.");

  script_tag(name:"insight", value:"The login and password for XDMCP is transmitted in plaintext.

  This makes the system vulnerable to Man-in-the-middle attacks, making it easy
  for an attacker to steal the credentials of a legitimate user by impersonating
  the XDMCP server. In addition to this, since XDMCP is not a ciphered protocol,
  an attacker has an easier time capturing the keystrokes entered by the user.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

port = 177;

if( ! get_udp_port_state( port ) )
  exit( 0 );

soc = open_sock_udp( port );
if( ! soc )
  exit( 0 );

# this magic info request packet
req = raw_string( 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00 );
send( socket:soc, data:req );
result = recv( socket:soc, length:1000 );
close( soc );
if( result && ( result[0] == raw_string( 0x00 ) ) &&
              ( result[1] == raw_string( 0x01 ) ) &&
              ( result[2] == raw_string(0x00 ) ) ) {
  log_message( port:port, protocol:"udp" );
}

exit( 0 );

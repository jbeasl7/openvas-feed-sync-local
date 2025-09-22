# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140152");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-08 11:18:12 +0100 (Wed, 08 Feb 2017)");
  script_name("SSL/TLS: Microsoft Remote Desktop Protocol STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("ms_rdp_detect.nasl");
  script_require_ports("Services/ms-wbt-server", 3389);
  script_mandatory_keys("rdp/detected");

  script_tag(name:"summary", value:"Checks if the remote Microsoft Remote Desktop Protocol (RDP) service supports the 'PROTOCOL_SSL' flag.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://msdn.microsoft.com/de-de/library/cc240500.aspx");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:3389, proto:"ms-wbt-server" );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# https://msdn.microsoft.com/de-de/library/cc240500.aspx

req = raw_string( 0x03,       # version
                  0x00,       # reserved
                  0x00, 0x13, # length (19)
                  0x0e,       # length (14)
                  0xe0,       # PDU type
                  0x00, 0x00, # dest ref
                  0x00, 0x00, # source ref
                  0x00,       # class
                  0x01,       # RDP negotiation request: type (1 byte): An 8-bit, unsigned integer that indicates the packet type. This field MUST be set to 0x01 (TYPE_RDP_NEG_REQ).
                  0x00,       # flags
                  0x08, 0x00, # length (8) # length (2 bytes): A 16-bit, unsigned integer that specifies the packet size. This field MUST be set to 0x0008 (8 bytes).
                  0x03, 0x00, 0x00, 0x00 # requested protocols. TLS security supported: TRUE, CredSSP supported: TRUE, EUARPDUS: FALSE
                );

send( socket:soc, data:req );
buf = recv( socket:soc, length:19 );
close( soc );
if( ! buf ) exit( 0 );

# https://msdn.microsoft.com/en-us/library/cc240501.aspx
#
# tpktHeader (4 bytes) + x224Ccf (7 bytes) + rdpNegData (8 bytes) = 19 bytes
if( strlen( buf ) != 19 ) exit( 0 );

type    = ord( buf[11] ); # type (1 byte):  An 8-bit, unsigned integer that indicates the packet type. This field MUST be set to 0x02 (TYPE_RDP_NEG_RSP).
flags   = ord( buf[12] ); # flags (1 byte): An 8-bit, unsigned integer that contains protocol flags.
len     = ord( buf[13] ) | ( ord( buf[14]) << 8 ); # length (2 bytes).
sproto  = ord( buf[15] ) | ( ord( buf[16]) << 8 ) | ( ord( buf[17]) << 16) | ( ord( buf[18] ) << 24 ); # selectedProtocol (4 bytes)

# length (2 bytes): A 16-bit, unsigned integer that specifies the packet size. This field MUST be set to 0x0008 (8 bytes)
if( len != 8 ) exit( 0 );

# selectedProtocol:
# 0x00000000 = Standard RDP Security
# 0x00000001 = TLS 1.0, 1.1 or 1.2
# 0x00000002 = CredSSP (https://msdn.microsoft.com/en-us/library/cc240806.aspx)

if( type == 2 && ( sproto == 1 || sproto == 2 ) ) {
  set_kb_item( name:"msrdp/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"msrdp" );
  log_message( port:port, data:"The remote Microsoft Remote Desktop Protocol (RDP) service supports the 'PROTOCOL_SSL' flag." );
}

exit( 0 );

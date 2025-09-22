# SPDX-FileCopyrightText: 2003 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11964");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1108");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SIP Express Router Missing To in ACK DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Noam Rathaus");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2003-06.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6904");

  script_tag(name:"solution", value:"Upgrade to version 0.8.10.");

  script_tag(name:"summary", value:"The remote host is a SIP Express Router (SER).

  The SER product has been found to contain a vulnerability where ACKs
  requests without a To header, when SER has been enabled to use the SL module,
  can be used to crash the product.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

if( ! banner = sip_get_banner( port:port, proto:proto ) )
  exit( 0 );

# Sample: Sip EXpress router (0.8.12 (i386/linux))
if( egrep( pattern:"Sip EXpress router \((0\.[0-7]\.|0\.8\.[0-9]) ", string:banner ) ) {
  security_message( port:port, protocol:proto );
  exit( 0 );
}

exit( 99 );

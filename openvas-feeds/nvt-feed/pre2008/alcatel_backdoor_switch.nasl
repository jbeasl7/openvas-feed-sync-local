# SPDX-FileCopyrightText: 2005 deepquest
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11170");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-1272");
  script_name("Alcatel OmniSwitch 7700/7800 switches backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 deepquest");
  script_family("Malware");
  script_dependencies("find_service.nasl", "telnet.nasl");
  script_require_ports(6778);

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-32.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6220");

  script_tag(name:"solution", value:"Block access to port 6778/TCP or update to
  AOS 5.1.1.R02 or AOS 5.1.1.R03.");

  script_tag(name:"summary", value:"The remote host seems to be a backdoored
  Alcatel OmniSwitch 7700/7800.");

  script_tag(name:"impact", value:"An attacker can gain full access to any device
  running AOS version 5.1.1, which can result in, but is not limited to,
  unauthorized access, unauthorized monitoring, information leakage,
  or denial of service.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");
include("port_service_func.inc");

port = 6778;

# For the case if "unscanned_closed = no" is used.
# Also used as the check below only checks if it
# is possible to open a socket to this port.
if( ! service_verify( port:port, proto:"telnet" ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

data = telnet_get_banner( port:port );
telnet_close_socket( socket:soc, data:data );

if( data ) {
  security_message( port:port, data:'Banner:\n' + data );
  exit( 0 );
}

exit( 99 );

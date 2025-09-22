# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10832");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0595");
  script_name("Kcms Profile Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("RPC");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gb_rpc_portmap_tcp_detect.nasl", "gather-package-list.nasl", "os_detection.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected");

  script_xref(name:"URL", value:"http://packetstorm.decepticons.org/advisories/ibm-ers/96-09");
  script_xref(name:"URL", value:"http://www.eeye.com/html/Research/Advisories/AD20010409.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2605");

  script_tag(name:"solution", value:"Disable suid, side effects are minimal.");

  script_tag(name:"summary", value:"The Kodak Color Management System service is running.

  The KCMS service on Solaris 2.5 could allow a local user
  to write to arbitrary files and gain root access.

  Patches: 107337-02 SunOS 5.7 has been released
  and the following should be out soon:
  111400-01 SunOS 5.8, 111401-01 SunOS 5.8_x86");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("rpc.inc");
include("host_details.inc");
include("os_func.inc");
include("byte_func.inc");
include("solaris.inc");

version = get_ssh_solosversion();
if( version && ereg( pattern:"5\.1[0-9]", string:version ) ) exit(0);

RPC_PROG = 100221;
tcp = FALSE;
port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_UDP );
if( ! port ) {
  port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_TCP );
  tcp = TRUE;
}

if( port ) {
  if( os_host_runs( "Solaris (2\.[56]|[7-9])") != "no" ) {
    if( tcp ) {
      security_message( port:port );
    } else {
      security_message( port:port, protocol:"udp" );
    }
    exit( 0 );
  }
}

exit( 99 );

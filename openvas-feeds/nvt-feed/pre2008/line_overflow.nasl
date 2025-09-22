# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11175");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Too long line");
  script_category(ACT_FLOOD);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"It was possible to kill the service by sending a single long
  text line.");

  script_tag(name:"impact", value:"A cracker may be able to use this flaw to crash your software
  or even execute arbitrary code on your system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = unknownservice_get_port( nodefault:TRUE );

s = open_sock_tcp(port);
if(!s)
  exit(0);

line = string(crap(512), "\r\n");
send(socket: s, data: line);
r = recv(socket:s, length:1); # Make sure data arrived
close(s);
s = open_sock_tcp(port);
if(s) {
  close(s);
  exit(99);
} else {
  security_message(port:port);
}

exit(0);

# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20162");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_name("Cheops NG clear text authentication");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("General");
  script_dependencies("cheopsNG_detect.nasl");
  script_mandatory_keys("cheopsNG/password");

  script_tag(name:"solution", value:"Configure Cheops to run on top of SSL or block this port
  from outside communication if you want to further restrict the use of Cheops.");

  script_tag(name:"summary", value:"A Cheops NG agent is running on the remote host.

  Users with a valid account on this machine can connect
  to this service and use it to map the network, port scan
  machines and identify running services.

  Passwords are transmitted in clear text and could be sniffed.
  More, using this Cheops agent, it is possible to brute force
  login/passwords on this system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

port = get_kb_item("cheopsNG/password");
if(port && get_port_transport(port) == ENCAPS_IP ) {
  security_message(port:port);
  exit(0);
}

exit(99);

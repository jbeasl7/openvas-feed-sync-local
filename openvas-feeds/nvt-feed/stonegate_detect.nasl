# SPDX-FileCopyrightText: 2005 it.sec/Holger Heimann
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11762");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("StoneGate Client Authentication Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 it.sec/Holger Heimann");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/SG_ClientAuth", 2543);

  script_tag(name:"summary", value:"A StoneGate firewall login is displayed.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

## Heres the real dialog:
#
# telnet www.xxxxxx.de 2543
#  Trying xxx.xxx.xxx.xxx ...
#  Connected to www.xxxxs.de.
#  Escape character is '^]'.
#  StoneGate firewall (xx.xx.xx.xx)
#  SG login:

port = service_get_port(default:2543, proto:"SG_ClientAuth");

banner = get_kb_item("FindService/tcp/" + port + "/spontaneous");
if(!banner)
  exit(0);

r = egrep(pattern:"(StoneGate firewall|SG login:)", string:banner);
if(!r)
  exit(0);

report = "A StoneGate firewall client authentication login is displayed.

Here is the banner :

" + r;

log_message(port:port, data:report);
exit(0);

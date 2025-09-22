# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10675");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CheckPoint Firewall-1 Telnet Authentication Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(259);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"A Firewall-1 Client Authentication Server is running on this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 259;
if(!get_port_state(port))
  exit(0);

data = telnet_get_banner(port:port);
if(data && "Check Point FireWall-1 Client Authentication Server running on" >< data)
  log_message(port:port);

exit(0);

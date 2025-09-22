# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100651");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_name("ClamAV Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  script_tag(name:"summary", value:"TCP based detection of ClamAV.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port(default:3310, proto:"clamd");

if(!soc = open_sock_tcp(port))
  exit(0);

req = string("VERSION\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:256);
close(soc);

if(!buf || "clamav" >!< tolower(buf))
  exit(0);

install = port + "/tcp";
version = "unknown";

# ClamAV 0.97.5
# ClamAV 0.100.3/25513/Wed Jul 17 08:15:42 2019
# clamav 1.4.3
vers = eregmatch(pattern:"clamav ([0-9.]+)", string:tolower(buf));
if(vers[1])
  version = vers[1];

set_kb_item(name:"clamav/detected", value:TRUE);
set_kb_item(name:"clamav/remote/detected", value:TRUE);
set_kb_item(name:"clamav/clamd/detected", value:TRUE);
set_kb_item(name:"clamav/clamd/port", value:port);

set_kb_item(name:"clamav/clamd/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0]);

exit(0);

# SPDX-FileCopyrightText: 2005 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10273");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Samba Web Administration Tool SWAT Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/swat", 901);

  script_tag(name:"summary", value:"HTTP based detection of the Samba Web Administration Tool
  (SWAT).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = service_get_port(proto:"swat", default:1);
if(port == 1) {
  nosvc = TRUE;
  port = 901;
}

if(!get_port_state(port))
  exit(0);

# nb: Should be always before the first http_open_socket() call
req = http_get(item:"/", port:port);

if(!soc = http_open_socket(port))
  exit(0);

send(socket:soc, data:req);
banner = http_recv(socket:soc);
http_close_socket(soc);

quote = raw_string(0x22);
expect = "WWW-Authenticate: Basic realm=" + quote + "SWAT" + quote;
if(expect >< banner) {
  log_message(port:port);
  if(nosvc)
    service_register(proto:"swat", port:port);
}

exit(0);

# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11945");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("sxdesign SIPd Status Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6050);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Access to this port should be restricted to trusted users only");

  script_tag(name:"summary", value:"A SIP status server is running on this port.");

  script_tag(name:"impact", value:"An attacker may use the remote status information of this server to
  collect sensitive information such as server version, emails,
  and ip addresses (internal and external).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:6050);
res = http_get_cache(item:"/", port:port);
if(res && "SIP Server Status" >< res && "Server Version" >< res)
  log_message(port:port);

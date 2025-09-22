# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103125");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("eDirectory DHost Web Server Detection");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8028, 8030);
  script_mandatory_keys("DHost/banner");

  script_tag(name:"summary", value:"The eDirectory DHost web server is running at this port.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("global_settings.inc");

port = http_get_port(default:8028);

banner = http_get_remote_headers(port:port);
if(banner !~ "Server: DHost/[0-9.]+ HttpStk")exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

if("DHost Console" >< buf && "DS Trace" >< buf && "NDS iMonitor" >< buf) {

  set_kb_item(name: string("www/", port, "/eDirectory_DHost"), value: TRUE);

  if(report_verbosity > 0) {
    log_message(port:port);
  }
}

exit(0);

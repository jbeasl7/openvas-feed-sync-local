# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17584");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Checkpoint Secure Platform detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports(443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Checkpoint Secure Platform.

  The script sends a connection request to the server and attempts to
  detect Checkpoint Secure Platform from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = 443;
if(!get_port_state(port))
  exit(0);

rep = http_get_cache(item:"/deploymentmanager/index.jsp", port:port);
if(!rep)
  exit(0);

#<title>SecurePlatform NG with Application Intelligence (R55) </title>
if("<title>SecurePlatform NG with Application Intelligence " >< rep) {

  install = "/deploymentmanager";
  cpe = "cpe:/a:checkpoint:secure_platform_ng";
  set_kb_item(name:"checkpoint_secure_platform/installed",value:TRUE);

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Checkpoint Secure Platform", version:"unknown", install:install, cpe:cpe, concluded:"<title>SecurePlatform NG with Application Intelligence"),
              port:port);
}

exit(0);

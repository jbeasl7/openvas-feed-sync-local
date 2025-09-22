# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812371");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-03 10:21:46 +0530 (Wed, 03 Jan 2018)");
  script_name("Building Automation Systems BAS-Device Web Detection");

  script_tag(name:"summary", value:"Detection of running version of
  Building Automation System device.

  This script sends an HTTP GET request and tries to ensure the presence of
  Building Automation System devices.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

basPort = http_get_port(default:80);

rcvRes = http_get_cache(port:basPort, item:"/");
if(rcvRes =~ "Server: BAS([0-9A-Z]+) HTTPserv:00002")
{
  basVer = "Unknown";
  set_kb_item(name:"BAS/Device/Installed", value:TRUE);
  model = eregmatch(pattern:" BAS([0-9A-Z]+) ", string:rcvRes);
  if(model[1])
  {
    set_kb_item(name:"BAS/Device/Model", value:model[1]);
    Model = model[1];
  } else {
    Model = "Unknown";
  }

  cpe = 'cpe:/h:building_automation_systems:bas';

  register_product(cpe:cpe, location:"/", port:basPort, service:"www");

  log_message(data: build_detection_report(app: "Building Automation Systems BAS-Device",
                                           version: basVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: "BAS Device Version:" + basVer + ", Model:" + Model),
                                           port: basPort);
}

exit(0);

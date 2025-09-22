# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808245");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-04 17:44:06 +0530 (Mon, 04 Jul 2016)");

  script_name("Option CloudGate Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Option CloudGate devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(item: "/", port: port);

if(("<title>CloudGate</title>" >< res && "Powered by Cloudgate" >< res && "js/cg.js" >< res) ||
   ('document.title = "CloudGate"' >< res && "api/replacementui" >< res)) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "option/cloudgate/detected", value: TRUE);
  set_kb_item(name: "option/cloudgate/http/port", value: port);
  set_kb_item(name: "option/cloudgate/http/" + port + "/version", value: version);
  set_kb_item(name: "option/cloudgate/http/" + port + "/model", value: model);
}

exit(0);

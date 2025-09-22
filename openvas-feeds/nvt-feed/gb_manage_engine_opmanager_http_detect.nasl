# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805471");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-20 11:52:44 +0530 (Fri, 20 Mar 2015)");
  script_name("ManageEngine OpManager Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of ManageEngine OpManager.

  The script sends a connection request to the server and attempts to detect ManageEngine OpManager
  and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-monitoring/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 8060);

foreach dir(make_list_unique("/", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/LoginPage.do";
  buf = http_get_cache(item: url, port: port);

  if ("ManageEngine" >< buf && "OpManager" >< buf && "opmLoginFieldHolder" >< buf) {
    version = "unknown";

    set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
    set_kb_item(name: "manageengine/opmanager/detected", value: TRUE);
    set_kb_item(name: "manageengine/opmanager/http/detected", value: TRUE);
    set_kb_item(name: "manageengine/opmanager/http/port", value: port);
    set_kb_item(name: "manageengine/opmanager/http/" + port + "/location", value: install);

    # SRC="/cachestart/124022/cacheend/apiclient/fluidicv2/javascript/jquery/jquery-1.9.0.min.js"
    vers = eregmatch(pattern: "/cachestart/([0-9]+)/cacheend/", string: buf);
    if (!isnull(vers[1])) {
      set_kb_item(name: "manageengine/opmanager/http/" + port + "/concluded", value: vers[0]);
      version = vers[1];
    }

    set_kb_item(name: "manageengine/opmanager/http/" + port + "/version", value: version);

    exit(0);
  }
}

exit(0);

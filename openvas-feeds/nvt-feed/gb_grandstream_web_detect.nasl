# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114018");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-08 12:42:30 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream Web UI Detection");

  script_tag(name:"summary", value:"Detection of Grandstream Web UI.

  The script sends a connection request to the server and attempts to detect the Grandstream Web UI.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.grandstream.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if("<b>Grandstream Device Configuration</b>" >< res || '<font size="1">All Rights Reserved Grandstream Networks, Inc. 2006-2008</font>' >< res) {
   #Version can only be extracted after a successful login
   version = "unknown";
   install = "/";

   conclUrl = http_report_vuln_url(port: port, url: "/", url_only: TRUE);

   set_kb_item(name: "grandstream/webui/detected", value: TRUE);
   set_kb_item(name: "grandstream/webui/" + port + "/detected", value: TRUE);

   register_and_report_cpe(app: "Grandstream Web UI", ver: version, base: "cpe:/a:grandstream:web_ui:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Login required for version detection.");
}

exit(0);

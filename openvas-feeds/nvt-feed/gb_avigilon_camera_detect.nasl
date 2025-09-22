# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114025");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-28 15:29:31 +0200 (Tue, 28 Aug 2018)");
  script_name("Avigilon Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Avigilon Camera.

  This script sends an HTTP GET request and tries to ensure the presence of
  Avigilon Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage";
res = http_get_cache(port: port, item: url);

if("<title>Avigilon Camera Login</title>" >< res && ">User name:<" >< res &&
   ">Password:<" >< res) {

  version = "unknown";

  set_kb_item(name: "avigilon/camera/detected", value: TRUE);

  cpe = "cpe:/a:avigilon:avigilon_camera:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Avigilon Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);

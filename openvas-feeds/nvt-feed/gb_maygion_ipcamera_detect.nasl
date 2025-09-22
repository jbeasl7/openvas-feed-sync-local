# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114062");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-02-04 15:56:53 +0100 (Mon, 04 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MayGion IPCamera Detection");

  script_tag(name:"summary", value:"Detection of MayGion IPCamera.

  The script sends a connection request to the server and attempts to detect the web interface for MayGion IPCamera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("WebServer_IPCamera_Logo/banner");

  script_xref(name:"URL", value:"https://elinux.org/MayGion_MIPS_IPCam");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 81);
banner = http_get_remote_headers(port: port);

if(banner && "Server: WebServer(IPCamera_Logo)" >< banner){
  version = "unknown";
  install = "/";

  conclUrl = http_report_vuln_url(port: port, url: "/", url_only: TRUE);
  cpe = "cpe:/a:maygion:ip_camera:";

  set_kb_item(name: "maygion/ip_camera/detected", value: TRUE);
  set_kb_item(name: "maygion/ip_camera/" + port + "/detected", value: TRUE);

  register_and_report_cpe(app: "MayGion IPCamera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106469");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-12-13 16:56:55 +0700 (Tue, 13 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("McAfee VirusScan Enterprise Detection (HTTP, Linux)");

  script_tag(name:"summary", value:"Detection of McAfee VirusScan Enterprise for Linux.

  The script sends a HTTP connection request to the server and attempts to detect the presence of McAfee
  VirusScan Enterprise for Linux and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 55443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 55443);

res = http_get_cache(port: port, item: "/");

if ('gsProductTitle = "McAfee VirusScan Enterprise for Linux' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'gsProductSubtitle = "Version ([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version =  vers[1];
    set_kb_item(name: "mcafee/virusscan_enterprise_linux/version", value: version);
  }

  set_kb_item(name: "mcafee/virusscan_enterprise_linux/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:virusscan_enterprise_for_linux:");
  if (!cpe)
    cpe = 'cpe:/a:mcafee:virusscan_enterprise_for_linux';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "McAfee VirusScan Enterprise for Linux", version: version,
                                           install: "/",cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);

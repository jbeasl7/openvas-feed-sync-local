# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106935");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-11 08:49:25 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pelco VideoXpert Detection");

  script_tag(name:"summary", value:"Detection of Pelco VideoXpert.

The script sends a connection request to the server and attempts to detect Pelco VideoXpert.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.pelco.com/video-management-system/videoxpert");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/portal/");

if ("<title>VideoXpert Admin Portal</title>" >< res && "lilac/lilac.nocache.js" >< res) {
  version = "unknown";
  install = "/portal";

  set_kb_item(name: "pelco_videoxpert/installed", value: TRUE);

  cpe = 'cpe:/a:pelco:videoxpert';

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Pelco VideoXpert", version: version, install: install,
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);

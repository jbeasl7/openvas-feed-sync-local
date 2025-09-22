# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106243");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-14 13:50:44 +0700 (Wed, 14 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Opmantek NMIS Detection");

  script_tag(name:"summary", value:"Detection of Opmantek NMIS

The script attempts to identify Opmantek NMIS and to extract the version number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://opmantek.com/network-management-system-nmis/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/cgi-nmis8", "/cgi-nmis4", http_cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/") dir = "";

  url = dir + "/nmiscgi.pl";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("Network Management Information System" >< res && "www.opmantek.com" >< res) {
    version  = "unknown";

    ver = eregmatch(pattern: "NMIS ([0-9.]+([A-Z])?)", string: res);
    if (!isnull(ver[1])) {
     version = ver[1];
     set_kb_item(name: "opmantek_nmis/version", value: version);
    }

    set_kb_item(name: "opmantek_nmis/installed", value: TRUE);

    cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.]+)", base: "cpe:/a:opmantek:nmis:");
    if (!cpe)
      cpe = 'cpe:/a:opmantek:nmis';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Opmantek NMIS", version: version, install: install,
                                             cpe: cpe, concluded: ver[0]),
                port: port);
    exit(0);
  }
}

exit(0);

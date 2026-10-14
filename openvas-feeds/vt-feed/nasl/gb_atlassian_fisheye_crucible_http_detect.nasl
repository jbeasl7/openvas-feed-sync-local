# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140326");
  script_version("2026-10-13T05:50:50+0000");
  script_tag(name:"last_modification", value:"2026-10-13 05:50:50 +0000 (Tue, 13 Oct 2026)");
  script_tag(name:"creation_date", value:"2017-08-25 14:18:37 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian FishEye and Crucible Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Atlassian FishEye and Crucible.");

  script_xref(name:"URL", value:"https://www.atlassian.com/software/fisheye");
  script_xref(name:"URL", value:"https://www.atlassian.com/software/crucible");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/crucible", "/fisheye", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/";

  res = http_get_cache(port: port, item: url);

  if (('display-name="Fisheye and Crucible"' >< res || "<title>Log in to Fisheye and Crucible" >< res) &&
      res =~ "Page generated\s+[0-9]{4}\-") {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    vers = eregmatch(pattern: "\(Version:([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "atlassian/fisheye_crucible/detected", value: TRUE);
    set_kb_item(name: "atlassian/fisheye_crucible/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:fisheye:");
    if (!cpe)
      cpe = "cpe:/a:atlassian:fisheye";

    cpe2 =  build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:crucible:");
    if (!cpe)
      cpe = "cpe:/a:atlassian:crucible";

    register_product(cpe: cpe, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port);

    log_message(data: build_detection_report(app: "Atlassian FishEye and Crucible", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807499");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-03-18 12:26:14 +0530 (Fri, 18 Mar 2016)");
  script_name("Kaltura Video Platform Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                       "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                       "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Kaltura Video Platform.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 80);

if(!http_can_host_php(port: port))
  exit(0);

foreach dir(make_list_unique("/", "/Kaltura", "/kvd", http_cgi_dirs(port: port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  res = http_get_cache(item: dir + "/start/index.php", port: port);

  if(res =~ "^HTTP/1\.[01] 200" && res =~ "title>Kaltura Video Platf(ro|or)m") {

    version = "unknown";
    edition = "";

    ver = eregmatch(pattern: "Community Edition (Kaltura Server )?([0-9.-]+)", string: res);
    if(!isnull(ver[2])) {
      version = ver[2];
      set_kb_item(name: "kaltura/version", value: version);
      set_kb_item(name: "kaltura/community/installed", value: TRUE);
      edition = "Community ";
    }
    else {
      ver = eregmatch(pattern: "OnPrem.* ([0-9.-]+).</h1>", string: res);
      if (!isnull(ver[1])) {
        version = ver[1];
        set_kb_item(name: "kaltura/version", value: version);
        set_kb_item(name: "kaltura/onprem/installed", value: TRUE);
        edition = "On-Prem ";
      }
    }

    set_kb_item(name: "kaltura/detected", value: TRUE);
    set_kb_item(name: "kaltura/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp:"^([0-9.-]+)", base: "cpe:/a:kaltura:kaltura:");
    if(!cpe)
      cpe = "cpe:/a:kaltura:kaltura";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Kaltura " + edition + "Edition",
                                             version: version,
                                             install: install,
                                             cpe: cpe,
                                             concluded: ver[0]),
                port: port);
    exit(0);
  }
}

exit(0);

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100838");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Evaria ECMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Evaria ECMS.");

  script_xref(name:"URL", value:"http://www.evaria.com/en/?view=ecms");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/ecms","/cms", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/?view=home";

  res = http_get_cache(port: port, item: url);
  if (!res)
    continue;

  if ('content="evaria.com - ecms - evaria content management system"' >< res &&
      egrep(pattern: "Powered by: <a [^>]+>ecms", string: res)) {
    version = "unknown";

    vers = eregmatch(string: res, pattern: "ecms v([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1]))
       version = vers[1];

    set_kb_item(name: "evaria/ecms/detected", value: TRUE);
    set_kb_item(name: "evaria/ecms/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:evaria:ecms:");
    if (!cpe)
      cpe = "cpe:/a:evaria:ecms";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Evaria ECMS", version: version, install: install,
                                             cpe: cpe, concluded: vers[0],
                                             concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
                port: port);
    exit(0);
 }
}

exit(0);

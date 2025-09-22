# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147893");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2022-03-31 09:54:46 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WHMCompleteSolution (WHMCS) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of WHMCompleteSolution (WHMCS).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.whmcs.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cart", "/shop", "/whmcs", "/bill", "/support", "/management", http_cgi_dirs(port:port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");

  if ("whmcsBaseUrl" >< res || ">WHMCompleteSolution<" >< res ||
      egrep(pattern: "[Ss]et-[Cc]ookie\s*:\s*WHMCS[0-9A-Za-z]{12}=", string: res, icase: FALSE)) {
    version = "unknown";

    set_kb_item(name: "whmcs/detected", value: TRUE);
    set_kb_item(name: "whmcs/http_detected", value: TRUE);

    cpe = "cpe:/a:whmcs:whmcompletesolution";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "WHMCompleteSolution (WHMCS)", version: version,
                                             install: install, cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);

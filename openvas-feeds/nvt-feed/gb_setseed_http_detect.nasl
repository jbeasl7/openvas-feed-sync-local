# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103326");
  script_version("2025-07-23T05:44:58+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:58 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-11-03 08:00:00 +0100 (Thu, 03 Nov 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SetSeed CMS Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.setseed.com/");

  script_tag(name:"summary", value:"HTTP based detection of the SetSeed CMS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/setseed-hub/";
  buf = http_get_cache(item:url, port:port);
  if(!buf)
    continue;

  if(concl = egrep(pattern:"<title>SetSeed Hub", string:buf, icase:TRUE)) {

    version = "unknown";
    concluded = "  " + chomp(concl);
    conclUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);

    vers = eregmatch(string:buf, pattern:"Version: ([0-9.]+)[^<]*<", icase:TRUE);
    if(vers[1]) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    set_kb_item(name:"setseed/detected", value:TRUE);
    set_kb_item(name:"setseed/http/detected", value:TRUE);

    register_and_report_cpe(app:"SetSeed CMS",
                            ver:version,
                            concluded:concluded,
                            base:"cpe:/a:setseed:setseed_cms:",
                            expr:"^([0-9.]+)",
                            insloc:install,
                            regService:"www",
                            regPort:port,
                            conclUrl:conclUrl);
    exit(0);
  }
}

exit(0);

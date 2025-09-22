# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808098");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-06-28 13:02:55 +0530 (Tue, 28 Jun 2016)");
  script_name("OPAC KpwinSQL Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  OPAC KpwinSQL.

  This script sends an HTTP GET request and tries to ensure the presence of OPAC KpwinSQL
  from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

opac_port = http_get_port(default:80);
if(! http_can_host_php(port:opac_port)) exit(0);

foreach dir(make_list_unique("/", "/OPAC", "/kpwinSQL", "/OPAC-kpwinSQL", http_cgi_dirs(port:opac_port)))
{
  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + '/index.php';
  rcvRes = http_get_cache(item:url, port:opac_port);

  if(rcvRes && "KPWIN" >< rcvRes && rcvRes =~ "<title>WWW OPAC.*KpwinSQL </title" &&
     "OPACSQL" >< rcvRes && rcvRes =~ "^HTTP/1\.[01] 200")
  {
    version = "unknown";

    set_kb_item(name:"KpwinSQL/Installed", value:TRUE);

    cpe = "cpe:/a:opac:kpwinsql";

    register_product(cpe:cpe, location:install, port:opac_port, service:"www");

    log_message(data:build_detection_report(app:"KpwinSQL",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:opac_port);
    exit(0);
  }
}

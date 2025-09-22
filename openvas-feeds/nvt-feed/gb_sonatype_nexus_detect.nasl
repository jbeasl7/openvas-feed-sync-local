# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805324");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-20 13:00:12 +0530 (Tue, 20 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Sonatype Nexus.

  This script sends an HTTP GET request and tries to get the version from the response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.sonatype.org/nexus/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:8081);

banner = http_get_remote_headers(port:port);

if(banner && "erver: Nexus" >< banner) {
  version = "unknown";

  # Server: Nexus/3.0.2-02 (OSS)
  # Server: Nexus/3.17.0-01 (OSS)
  # Server: Nexus/2.14.1-01
  vers = eregmatch(pattern:"Server: Nexus.([0-9.]+(-[0-9]+)?)", string:banner, icase:TRUE);
  if(!isnull(vers[1])) {
    version = vers[1];
    install = "/";
  }

  set_kb_item(name:"nexus/installed",value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:sonatype:nexus:");
  if(!cpe)
    cpe = "cpe:/a:sonatype:nexus";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Sonatype Nexus", version:version, install:install, cpe:cpe,
                                          concluded:vers[0]),
              port:port);
  exit(0);
}

foreach dir (make_list_unique("/", "/nexus", http_cgi_dirs(port:port))) {
  install = dir;
  if(dir == "/") dir = "";

  ## if version is not available in banner request for '/#welcome' page
  url = dir + "/#welcome";
  res = http_get_cache(item:url, port:port);

  if(res && (">Sonatype Nexus<" >< res || ">Sonatype Nexus Professional<" >< res)) {
    version = "unknown";
    found = TRUE;
    conclurl = url;

    vers = eregmatch(pattern:"verssion=([0-9.]+(-[0-9]+)?)", string:res);
    if(!isnull(vers[1]))
      version = vers[1];
  } else {
    url = dir + "/#browse/welcome";
    res = http_get_cache(item:url, port:port);

    if("Nexus Repository Manager" >< res) {
      version = "unknown";
      found = TRUE;
      conclurl = url;

      # loading-prod.css?_v=3.15.2-01">
      vers = eregmatch(pattern:"_v=([0-9.-]+)", string:res);
      if(!isnull(vers[1]))
        version = vers[1];
    }
  }

  if(found) {

    set_kb_item(name:"nexus/installed",value:TRUE);

    cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:sonatype:nexus:");
    if(!cpe)
      cpe = "cpe:/a:sonatype:nexus";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Sonatype Nexus", version:version, install:install, cpe:cpe,
                                            concluded:vers[0], concludedUrl:conclurl),
                port:port);
    exit(0);
  }
}

exit(0);

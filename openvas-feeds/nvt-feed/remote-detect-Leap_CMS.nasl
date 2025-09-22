# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101025");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-04-30 23:11:17 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Leap CMS Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Leap CMS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

url = "/leap";
res = http_get_cache(item:url + "/", port:port);
if(!res)
  exit(0);

if(res =~ 'Powered by [^\r\n]+>Leap<') {

  install = url;
  version = "unknown";
  set_kb_item(name:"gowondesigns/leapcms/detected", value:TRUE);

  vers = eregmatch(pattern:'Powered by <a href="https?://leap\\.gowondesigns\\.com/">Leap</a> ([0-9.]+)', string:res, icase:TRUE);
  if(vers[1])
    version = vers[1];

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:gowondesigns:leap:");
  if(!cpe)
    cpe = "cpe:/a:gowondesigns:leap";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Leap CMS",
                                          version:version,
                                          concluded:vers[0],
                                          install:install,
                                          cpe:cpe),
              port:port);
}

exit(0);

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100385");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("RT: Request Tracker Detection");

  script_tag(name:"summary", value:"Detects the installed version of Request Tracker.

  This script sends an HTTP GET request and tries to get the version from the response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

http_port = http_get_port(default:80);

foreach dir( make_list_unique( "/rt", "/tracker", http_cgi_dirs( port:http_port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.html";
  buf = http_get_cache( item:url, port:http_port );
  if( buf == NULL ) continue;

  if(egrep(pattern: "&#187;&#124;&#171; RT.*Best Practical Solutions, LLC", string: buf, icase: TRUE))
  {
    vers = string("unknown");
    version = eregmatch(string: buf, pattern: "&#187;&#124;&#171; RT ([0-9.]+)(rc[0-9]+)?",icase:TRUE);

    if( !isnull(version[1]) && !isnull(version[2])) {
      vers=chomp(version[1]) + "." + chomp(version[2]);
    }
    else if ( !isnull(version[1]) && isnull(version[2])) {
      vers=chomp(version[1]);
    }

    tmp_version = string(vers, " under ", install);
    set_kb_item(name: string("www/", http_port, "/rt_tracker"), value: tmp_version);
    set_kb_item(name:"RequestTracker/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:best_practical_solutions:request_tracker:");
    if(!cpe)
      cpe = "cpe:/a:best_practical_solutions:request_tracker";

    register_product(cpe:cpe, location:install, port:http_port, service:"www");

    log_message(data: build_detection_report(app:"Request Tracker (RT)",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:vers),
                                             port:http_port);
  }
}

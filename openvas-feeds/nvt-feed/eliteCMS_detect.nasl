# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100221");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("eliteCMS Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running eliteCMS a free, PHP and MySQL driven Content Management
  System.");

  script_xref(name:"URL", value:"http://elitecms.elite-graphix.net/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir (make_list_unique("/cms", "/elite", http_cgi_dirs(port: port))) {
 install = dir;
 if( dir == "/" ) dir = "";

 url = dir + "/admin/login.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if (egrep(pattern: 'Elite CMS .* Admin Control Panel', string: buf, icase: TRUE) ||
     egrep(pattern: 'eliteCMS - The Lightweight CMS', string: buf, icase: TRUE)   ||
     egrep(pattern: 'Pow(o|e)red by <a [^>]+>Elite CMS', string: buf, icase: TRUE)) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "Version ([0-9.]+)",icase:TRUE);
    if (!isnull(version[1]))
       vers = version[1];

    set_kb_item(name: "elitecms/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:elitecms:elitecms:");
    if (!cpe)
      cpe = 'cpe:/a:elitecms:elitecms';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "eliteCMS", version: vers, install: install, cpe: cpe,
                                             concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);

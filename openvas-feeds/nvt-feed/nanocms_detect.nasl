# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100140");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("NanoCMS Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running NanoCMS, a content management system.");

  script_xref(name:"URL", value:"http://nanocms.in");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/cms", "/nanocms", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if ( dir == "/" ) dir = "";

  url = string(dir, "/data/nanoadmin.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if ( buf == NULL ) continue;

  if (egrep(pattern: 'NanoCMS Admin Login', string: buf, icase: TRUE)) {
    vers = "unknown";

    files = make_list("/gnu-license-mini.txt","/README%20FIRST.txt");

    foreach file (files) {
      url = dir + file;
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if( ! buf ) continue;

      version = eregmatch(string: buf, pattern: 'NanoCMS v([0-9.]+)',icase:TRUE);

      if ( !isnull(version[1]) ) {
         vers = version[1];
         concUrl = url;
         break;
      }
    }

    set_kb_item(name: "nanocms/detected", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:nanocms:nanocms:");
    if (!cpe)
      cpe = 'cpe:/a:nanocms:nanocms';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "NanoCMS", version: vers, install: install, cpe: cpe,
                                             concluded: version[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);

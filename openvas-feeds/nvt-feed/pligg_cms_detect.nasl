# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100374");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pligg CMS Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Pligg CMS, an open source CMS.");

  script_xref(name:"URL", value:"http://www.pligg.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

SCRIPT_DESC = "Pligg CMS Detection";

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/pligg", "/cms", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if(!buf)
    continue;

  if(egrep(pattern: "Copyright.*Pligg <a.*http://www.pligg.com.*Content Management System", string: buf, icase: TRUE)) {

    vers = string("unknown");

    url = string(dir, "/readme.html");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req,bodyonly:TRUE);

    if("Pligg Readme" >< buf) {
      version = eregmatch(string: buf, pattern: "Version ([0-9.]+)",icase:TRUE);
      if ( !isnull(version[1]) ) {
        vers=chomp(version[1]);
      }
    } else {

      url = string(dir, "/languages/lang_english.conf");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req,bodyonly:TRUE);

      if("Pligg English language" >< buf) {
        version = eregmatch(string: buf, pattern: "//<VERSION>([0-9.]+)</VERSION> ",icase:TRUE);
        if ( !isnull(version[1]) ) {
          vers=chomp(version[1]);
        }
      }
    }

    set_kb_item(name: "pligg/detected", value: TRUE);
    set_kb_item(name: string("www/", port, "/pligg"), value: string(vers," under ",install));
    if("unknown" >!< vers) {
      register_host_detail(name:"App", value:string("cpe:/a:pligg:pligg_cms:",vers), desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:pligg:pligg_cms"), desc:SCRIPT_DESC);
    }

    info = string("Pligg CMS Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);

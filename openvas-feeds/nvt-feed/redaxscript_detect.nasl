# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100121");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Redaxscript Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://redaxscript.com/");

  script_tag(name:"summary", value:"This host is running Redaxscript a free, PHP and MySQL driven
  Content Management System for small business and private websites.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit(0);

foreach dir( make_list_unique( "/redaxscript", "/cms", "/php", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/", port:port );
  if(!buf)
    continue;

  if( '"generator" content="Redaxscript' >< buf && 'Content could not be found.</p>' >!< buf ) {

    vers = "unknown";
    version = eregmatch(string:buf, pattern:'"generator" content="Redaxscript ([0-9.]+)"', icase:TRUE);

    if(version[1])
      vers = version[1];

    set_kb_item(name:"redaxscript/detected", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:redaxscript:redaxscript:");
    if(!cpe)
      cpe = "cpe:/a:redaxscript:redaxscript";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Redaxscript",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0]),
                                            port:port);
  }
}

exit(0);

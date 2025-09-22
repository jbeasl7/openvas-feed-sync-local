# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113191");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2018-05-22 14:26:37 +0200 (Tue, 22 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Coremail XT Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Coremail XT.");

  script_xref(name:"URL", value:"http://www.coremail.cn/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  buf = http_get_cache( item: url, port: port );

  if( 'href="/coremail' >< buf || 'action="/coremail' >< buf ) {

    set_kb_item( name: "coremail/detected", value: TRUE );
    set_kb_item( name: "coremail/http/detected", value: TRUE );

    version = "unknown";

    vers = eregmatch( pattern: "coremail/common/index_cmxt([0-9]+).jsp", string: buf );
    if( ! isnull( vers[1] ) && strlen( vers[1] ) >= 2 ) {
      vers_number = vers[1];
      version = vers_number[0] + "." + vers_number[1];
    }

    cpe = "cpe:/a:mailtech:coremail:";

    register_and_report_cpe( app: "Coremail XT",
                             ver: version,
                             concluded: vers[0],
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: install,
                             regPort: port,
                             conclUrl: install );

    exit( 0 );
  }
}

exit( 0 );

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113059");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-30 10:23:24 +0100 (Thu, 30 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks Services Server Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This scripts sends an HTTP GET request to figure out whether Cambium Networks Services Server is installed on the target host, and, if so, which version.");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/management/cns-server/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 80 );
foreach dir ( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  foreach file ( make_list( "/", "/index.html" ) ) {

    if( dir == "/" ) url = file;
    else url = dir + file;

    resp = http_get_cache( item: url, port: port );

    if( resp =~ "<title>Cambium Networks Services Server</title>" && resp =~ 'href="http://cambiumnetworks.com"' ) {

      version_match = eregmatch( pattern: "<i>\(([0-9.]+)\)</i>", string: resp );
      version = "unknown";
      if ( version_match[1] ) version = version_match[1];

      set_kb_item( name: "cambium-networks/services-server/detected", value: TRUE );
      register_and_report_cpe( app: "Cambium Networks Services Server", ver: version, concluded: version_match[0], base: "cpe:/a:cambium-networks:services-server:", expr: "^([0-9.]+)", insloc: dir, regPort: port );
      exit( 0 );
    }
  }
}


# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113267");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-09-13 13:37:00 +0200 (Thu, 13 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP NetWeaver AS Java Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SAP NetWeaver Application Server (AS)
  Java.");

  script_xref(name:"URL", value:"https://wiki.scn.sap.com/wiki/display/ASJAVA/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

foreach location( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  dir = location;
  if( dir == "/" )
    dir = "";

  url1 = dir + "/startPage";
  buf1 = http_get_cache( item: url1, port: port );

  url2 = dir + "/index.html";
  buf2 = http_get_cache( item: url2, port: port );
  if( ! buf1 && ! buf2 )
    continue;

  # server: SAP NetWeaver Application Server 7.49 / AS Java 7.50
  # server: SAP NetWeaver Application Server 7.49 / AS Java 7.40
  # server: SAP NetWeaver Application Server 7.22 / AS Java 7.31
  # server: SAP NetWeaver Application Server 7.20 / AS Java 7.30
  # Server: SAP J2EE Engine/7.00
  # <title>SAP NetWeaver Application Server Java</title>
  if( concl = egrep( string: buf1, pattern: "^(server\s*:\s*SAP NetWeaver Application Server [^/]*/ AS Java|\s*<title>SAP NetWeaver Application Server Java</title>)|server\s*:\s*SAP J2EE Engine", icase: TRUE ) ) {
    found = TRUE;
    concluded = chomp( concl );
    conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
  }

  if( concl = egrep( string: buf2, pattern: "^(server\s*:\s*SAP NetWeaver Application Server [^/]*/ AS Java|\s*<title>SAP NetWeaver Application Server Java</title>)", icase: TRUE ) ) {
    found = TRUE;

    if( concluded )
      concluded += '\n';
    concluded += chomp( concl );

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += http_report_vuln_url( port: port, url: url2, url_only: TRUE );
  }

  if( found ) {

    version = "unknown";

    set_kb_item( name: "sap/netweaver/as_java/detected", value: TRUE );
    set_kb_item( name: "sap/netweaver/as_java/http/detected", value: TRUE );
    set_kb_item( name: "sap/netweaver/as_java/port", value: port );
    set_kb_item( name: "sap/netweaver/as_java/location", value: location );

    # nb: NetWeaver Portal is running on NetWeaver AS Java. This is used so that we can throw active
    # VTs against both "just to be sure".
    set_kb_item( name:"sap/netweaver/as_java_or_portal/detected", value:TRUE );
    set_kb_item( name:"sap/netweaver/as_java_or_portal/http/detected", value:TRUE );

    # Additional generic KB keys to have a reference if NetWeaver AS (all variants like AS Java, AS
    # ABAP and so on) was detected.
    set_kb_item( name:"sap/netweaver/as/detected", value:TRUE );
    set_kb_item( name:"sap/netweaver/as/http/detected", value:TRUE );

    # And another set of generic KB keys for VTs where it is not fully clear which SAP products are
    # affected.
    set_kb_item( name:"sap/products/detected", value:TRUE );
    set_kb_item( name:"sap/products/http/detected", value:TRUE );

    ver = eregmatch( string: concluded, pattern: "server\s*:\s*SAP NetWeaver Application Server [^/]*/ AS Java ([0-9.]+)", icase: TRUE );
    if( isnull( ver[1] ) )
      ver = eregmatch( string: concluded, pattern: "server\s*:\s*SAP J2EE Engine/([0-9.]+)", icase: TRUE );

    if( ! isnull( ver[1] ) )
      version = ver[1];

    register_and_report_cpe( app: "SAP NetWeaver Application Server (AS) Java",
                             ver: version,
                             concluded: concluded,
                             base: "cpe:/a:sap:netweaver_application_server_java:",
                             expr: "([0-9.]+)",
                             insloc: location,
                             regPort: port,
                             regService: "www",
                             conclUrl: conclUrl );

    exit( 0 );
  }
}

exit( 0 );

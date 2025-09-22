# Copyright (C) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900612");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("PHPFusion Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.php-fusion.co.uk");

  script_tag(name:"summary", value:"HTTP based detection of PHPFusion.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/php-fusion", "/phpfusion", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  foreach files( make_list( "/home.php", "/news.php" ) ) {
    url = dir + files;
    res = http_get_cache( item:url, port:port );

    if( res =~ "X-Powered-By: PHP-?Fusion" || "PHP-Fusion Powered" >< res ||
        res =~ "Powered by <a href='https?://(www\.)?php-fusion\.(co\.uk|com)'>PHP-Fusion</a>" ||
        "powered by php-fusion" >< res ) {
      version = "unknown";

      # X-Powered-By: PHP-Fusion 9.03.20
      vers = eregmatch( pattern:"X-Powered-By: PHP-?Fusion ([0-9.]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }

      set_kb_item( name:"php-fusion/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:php-fusion:php-fusion:" );
      if( ! cpe )
        cpe = "cpe:/a:php-fusion:php-fusion";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"PHPFusion", version:version, install:install, cpe:cpe,
                                                concluded:vers[0], concludedUrl:concUrl ),
                   port:port );
      exit( 0 );
    }
  }
}

exit( 0 );

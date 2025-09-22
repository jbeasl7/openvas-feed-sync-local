# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107020");
  script_version("2021-07-12T14:00:54+0000");
  script_tag(name:"last_modification", value:"2021-07-12 14:00:54 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-07-04 19:31:49 +0200 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Python Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "apache_server_info.nasl", "apache_server_status.nasl",
                      "gb_apache_perl_status.nasl", "gb_apache_http_server_http_error_page_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("python_or_apache_status_info_error_pages/banner");

  script_tag(name:"summary", value:"HTTP based detection of Python.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

pattern = '^Server\\s*:[^\r\n]*C?[^_]Python/[0-9.]+';

# nb: Excluding the underscore before "python" because of "mod_python" installations
# Server: Werkzeug/1.0.1 Python/3.6.9
# Server: Apache/2.2.17 (Unix) mod_ssl/2.2.17 OpenSSL/0.9.8r DAV/2 PHP/5.3.4 mod_python/3.3.1 Python/2.6.1
# Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_wsgi/4.5.16 Python/3.4
# Server: Python/3.8 aiohttp/3.6.2
# Server: BaseHTTP/0.3 Python/2.7.13
# Server: WSGIServer/0.2 CPython/3.7.9
# Server: File/1.0.0 CPython/3.7.3
# nb: CPython is the original Python implementation we're detecting here.
if( ! banner || ! found_banner = egrep( pattern:pattern, string:banner, icase:TRUE ) ) {

  # From apache_server_info.nasl, apache_server_status.nasl, gb_apache_perl_status.nasl or gb_apache_http_server_http_error_page_detect.nasl
  foreach infos( make_list( "server-info", "server-status", "perl-status", "apache_error_page" ) ) {

    info = get_kb_item( "www/" + infos + "/banner/" + port );
    if( info && found_banner = egrep( pattern:pattern, string:info, icase:TRUE ) ) {
      detected = TRUE;

      if( infos == "apache_error_page" ) {
        url = get_kb_item( "www/apache_error_page/banner/location/" + port );
        if( ! url )
          url = ""; # nb: Shouldn't happen but just to be sure...
      } else {
        url = "/" + infos;
      }

      conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      concluded = get_kb_item( "www/" + infos + "/banner/concluded/" + port );

      break;
    }
  }

  if( ! detected )
    exit( 0 );

} else {
  found_banner = chomp( found_banner );
  concluded = found_banner;
}

install = port + "/tcp";
vers = "unknown";

version = eregmatch( string:found_banner, pattern:"C?[^_]Python/([0-9.]+)", icase:TRUE );
if( ! isnull( version[1] ) )
  vers = version[1];

set_kb_item( name:"python/detected", value:TRUE );
set_kb_item( name:"python/http/detected", value:TRUE );
set_kb_item( name:"python/http/port", value:port );
set_kb_item( name:"python/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + vers + "#---#" + concluded + "#---#" + conclurl );

exit( 0 );
# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113057");
  script_version("2021-06-17T10:14:19+0000");
  script_tag(name:"last_modification", value:"2021-06-17 10:14:19 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Opencast Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Opencast.");

  script_xref(name:"URL", value:"https://www.opencast.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 443 );

foreach dir( make_list_unique( "/", "/admin-ng", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( make_list( "/", "/login.html" ) ) {

    url = dir + file;
    resp = http_get_cache( item: url, port: port );

    if( resp =~ "<title>Opencast[^<]{0,}" && ( 'version.version"> Opencast' >< resp || 'href="http://www.opencastproject.org"' >< resp  ||
                                               "<span>Welcome to Opencast</span>" >< resp || 'translate="LOGIN.WELCOME">' >< resp ) ) {

      set_kb_item( name: "opencast/detected", value: TRUE );
      version = "unknown";
      # nb: Opencast features different bundles. Using the prefix here to make sure the correct one is being checked.
      version_url = "/sysinfo/bundles/version?prefix=opencast";

      resp = http_get_cache( item: version_url, port: port );

      # {"consistent":true,"version":"8.4.0","buildNumber":"8c9c359"}
      # {"versions":[{"version":"8.3.0"},{"version":"8.6.0"}],"consistent":false}
      # {"last-modified":1623888039977,"consistent":true,"version":"9.0.0.SNAPSHOT","buildNumber":"5598d90"}
      #
      # nb: Using the greedy quantifier "*" to match the last occurrence of "version", assuming the highest one comes last.
      # Also making the last dot and digits optional, as they might just use "major.minor" format in the future.
      version_match = eregmatch( pattern: '.*"version":"([0-9]+\\.[0-9]+\\.?([0-9]+)?)', string: resp );

      if( version_match[1] ) {
        version = version_match[1];
        concluded_url = http_report_vuln_url( port:port, url:version_url, url_only:TRUE );
      }

      register_and_report_cpe( app: "Opencast", ver: version, concluded: version_match[0], base: "cpe:/a:opencast:opencast:", expr: "([0-9.]+)", insloc: install, regService: "www", regPort: port, conclUrl: concluded_url );

      exit( 0 );
    }
  }
}

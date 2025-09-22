# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108751");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2020-04-17 11:38:17 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Control WebPanel / CentOS WebPanel (CWP) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2030);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Control WebPanel / CentOS WebPanel
  (CWP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:2030 );

# nb: End-User Panel
url_up = "/";
res_up = http_get_cache( port:port, item:url_up );
banner_up = http_get_remote_headers( port:port, file:url_up );

# nb: root/Admin Panel
url_ap = "/login/index.php";
res_ap = http_get_cache( port:port, item:url_ap );
banner_ap = http_get_remote_headers( port:port, file:url_ap );

found = FALSE;
conclup = FALSE;
conclap = FALSE;
concluded = ""; # nb: To make openvas-nasl-lint happy...

# nb:
# - This is for the End-User Panel
# - Product got renamed in the past
# - Some pattern below even existed on/for the "new" variant/product name
detection_patterns_up = make_list(
  "^[Ss]erver\s*:\s*cwpsrv",
  "<title>CWP \| User</title>",
  '<a href="https?://(www\\.)?(control|centos)-webpanel\\.com" target="_blank">CWP (CentOS|Control) Web ?Panel\\.</a>',
  # <strong>powered by</strong></font><strong> CentOS-WebPanel.com</strong></h1>
  # alt="[ Powered by CentOS-WebPanel ]"></a>
  # <title>HTTP Server Test Page powered by CentOS-WebPanel-apache.com</title>
  # nb: The pattern below has been already updated to catch possible renamings in the future
  "[Pp]owered by.* (CentOS|Control)[- ]Web ?Panel",
  # src="/login/cwp_theme/original/img/new_logo_small.png"></a>
  # <script src="/login/cwp_theme/original/js/jquery-3.1.1.min.js"></script>
  # <link href="/login/cwp_theme/original/css/bootstrap.min.css" rel="stylesheet">
  '(src|href)="/login/cwp_theme/[^<]+/(img|js|css)/[^<]+'
);

# nb:
# - This is for the root/Admin Panel
# - Product got renamed in the past
detection_patterns_ap = make_list(
  "^[Ss]erver\s*:\s*cwpsrv",
  '<a href="https?://(www\\.)?(centos|control)-webpanel\\.com" target="_blank">(CentOS|Control) Web ?Panel</a>',
  "<title>Login \| (CentOS|Control) Web ?Panel</title>"
);

foreach pattern_up( detection_patterns_up ) {

  if( "cwpsrv" >< pattern_up )
    concl = egrep( string:banner_up, pattern:pattern_up, icase:FALSE );
  else
    concl = egrep( string:res_up, pattern:pattern_up, icase:FALSE );

  concl = chomp( concl );

  if( concl ) {

    # nb: Minor formatting change for the reporting. The egrep() above might include multiple
    # lines so we need to split them first.
    split_lines = split( concl, keep:FALSE );
    foreach split_line( split_lines ) {

      split_line = ereg_replace( string:split_line, pattern:"^(\s+)", replace:"" );

      # nb: Only include the cwp_theme result once as this would make the reporting too big
      # otherwise...
      if( "/cwp_theme/" >< split_line && "/cwp_theme/" >< concluded )
        continue;

      # nb: Avoid duplicated entries for e.g. the Server banner.
      if( split_line >!< concluded ) {
        if( concluded )
          concluded += '\n';
        concluded +=  "  " + split_line;
      }
    }

    conclup = TRUE;
    found++;
  }
}

foreach pattern_ap( detection_patterns_ap ) {

  if( "cwpsrv" >< pattern_ap )
    concl = egrep( string:banner_ap, pattern:pattern_ap, icase:FALSE );
  else
    concl = egrep( string:res_ap, pattern:pattern_ap, icase:FALSE );

  concl = chomp( concl );

  if( concl ) {

    # nb: Minor formatting change for the reporting. The egrep() above might include multiple
    # lines so we need to split them first.
    split_lines = split( concl, keep:FALSE );
    foreach split_line( split_lines ) {

      split_line = ereg_replace( string:split_line, pattern:"^(\s+)", replace:"" );

      # nb: Only include the cwp_theme result once as this would make the reporting too big
      # otherwise...
      if( "/cwp_theme/" >< split_line && "/cwp_theme/" >< concluded )
        continue;

      # nb: Avoid duplicated entries for e.g. the Server banner.
      if( split_line >!< concluded ) {
        if( concluded )
          concluded += '\n';
        concluded +=  "  " + split_line;
      }
    }

    conclap = TRUE;
    found++;
  }
}

# nb: Regex pattern are (currently) strict enough to use one single found pattern as a "proof" for
# the existence of the product.
if( found ) {

  version = "unknown";
  install = "/";

  if( conclap )
    conclUrl = http_report_vuln_url( port:port, url:url_ap, url_only:TRUE );

  if( conclup ) {
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += http_report_vuln_url( port:port, url:url_up, url_only:TRUE );
  }

  set_kb_item( name:"centos_webpanel/detected", value:TRUE );
  set_kb_item( name:"centos_webpanel/http/detected", value:TRUE );
  set_kb_item( name:"centos_webpanel/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#" + conclUrl );
}

exit( 0 );

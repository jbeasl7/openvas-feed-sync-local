# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19473");
  script_version("2022-05-12T09:32:01+0000");
  script_cve_id("CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MantisBT < 1.0.0rc2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112786017426276&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14604");

  script_tag(name:"solution", value:"Update to version 1.0.0rc2 or later.");

  script_tag(name:"summary", value:"MantisBT is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - MantisBT failed to sanitize user-supplied input to the 'g_db_type' parameter of the
  'core/database_api.php' script.

  - Multiple cross-site scripting (XSS) issues");

  script_tag(name:"impact", value:"Provided PHP's 'register_globals' setting is enabled, an attacker
  may be able to exploit this to connect to arbitrary databases as well as scan for arbitrary open
  ports, even on an internal network.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = info["version"];
dir = info["location"];

if( dir == "/" )
  dir = "";

# nb: request a bogus db driver.
url = dir + "/core/database_api.php?g_db_type=vt-test";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
if( ! res )
  exit( 0 );

# There's a problem if the requested driver file is missing.
# nb: this message occurs even with PHP's display_errors disabled.
if( "Missing file: " >< res && "/adodb/drivers/adodb-vt-test.inc.php" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_less( version:vers, test_version:"1.0.0rc2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0rc2", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

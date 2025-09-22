# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103333");
  script_cve_id("CVE-2011-4415");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-15 12:33:51 +0100 (Tue, 15 Nov 2011)");
  script_version("2022-04-28T13:38:57+0000");
  script_name("Apache HTTP Server 'ap_pregsub()' Function Local Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50639");
  script_xref(name:"URL", value:"http://www.halfdog.net/Security/2011/ApacheModSetEnvIfIntegerOverflow/");
  script_xref(name:"URL", value:"http://www.gossamer-threads.com/lists/apache/dev/403775");

  script_tag(name:"affected", value:"Apache HTTP Server 2.0.x through 2.0.64 and 2.2.x through
  2.2.21 are vulnerable. Other versions may also be affected.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a local denial-of-service
  vulnerability because of a NULL-pointer dereference error or a memory exhaustion.");

  script_tag(name:"impact", value:"Local attackers can exploit this issue to trigger a NULL-pointer
  dereference or memory exhaustion, and cause a server crash, denying service to legitimate users.

  Note: To trigger this issue, 'mod_setenvif' must be enabled and the attacker should be able
  to place a malicious '.htaccess' file on the affected webserver.");

  script_tag(name:"solution", value:"Update to the most recent version of Apache HTTP Server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.0.64" ) ||
    version_in_range( version:vers, test_version:"2.2", test_version2:"2.2.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
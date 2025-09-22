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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800827");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1890");
  script_name("Apache HTTP Server 'mod_proxy_http.c' Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35565");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1773");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=790587&r2=790586&pathrev=790587");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause Denial of Service
  to the legitimate user by CPU consumption.");

  script_tag(name:"affected", value:"Apache HTTP Server version prior to 2.3.3.");

  script_tag(name:"insight", value:"The flaw is due to error in 'stream_reqbody_cl' function in 'mod_proxy_http.c'
  in the mod_proxy module. When a reverse proxy is configured, it does not properly
  handle an amount of streamed data that exceeds the Content-Length value via crafted requests.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a Denial of Service vulnerability.");

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

if( version_is_less( version:vers, test_version:"2.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.3", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100449");
  script_version("2023-02-01T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"creation_date", value:"2010-01-14 12:06:50 +0100 (Thu, 14 Jan 2010)");
  script_cve_id("CVE-2008-4360", "CVE-2008-4359");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Lighttpd < 1.4.20 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31600");
  script_xref(name:"URL", value:"http://www.lighttpd.net/security/lighttpd_sa_2008_05.txt");
  script_xref(name:"URL", value:"http://www.lighttpd.net/security/lighttpd_sa_2008_06.txt");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_mandatory_keys("lighttpd/detected");

  script_tag(name:"summary", value:"Lighttpd is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security
  restrictions and obtain sensitive information. This may lead to other attacks.");

  script_tag(name:"affected", value:"Lighttpd versions prior to 1.4.20.");

  script_tag(name:"solution", value:"Update to version 1.4.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version: vers, test_version: "1.4.20" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.20" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

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

CPE = "cpe:/a:apache:mod_perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100162");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-1349");
  script_name("Apache mod_perl Path_Info Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_apache_mod_perl_http_detect.nasl");
  script_mandatory_keys("apache/mod_perl/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23192");

  script_tag(name:"summary", value:"According to its version number, the remote version of the
  Apache mod_perl module is prone to a remote denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause
  DoS conditions on the webserver running the mod_perl module.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"2.0.3" ) ||
    version_is_equal( version:vers, test_version:"2.0.2" ) ||
    version_is_equal( version:vers, test_version:"2.0.1" ) ||
    version_is_equal( version:vers, test_version:"1.29" ) ||
    version_is_equal( version:vers, test_version:"1.27" ) ||
    version_is_equal( version:vers, test_version:"1.99" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
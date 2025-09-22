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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800759");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1586");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP/HPE System Management Homepage (SMH) 'RedirectUrl' URI Redirection Vulnerability (HPSBMA02583)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58107");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39676");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c02518794");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/hp_system_management_homepage_url_redirection_abuse");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Input data passed to the 'RedirectUrl' parameter in
  'red2301.html' is not  being properly validated.");

  script_tag(name:"solution", value:"Update to version 6.2 or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to a URL
  redirection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to redirect
  to his choice of malicious site via the trusted vulnerable SMH url or aid in phishing attacks.");

  script_tag(name:"affected", value:"HP/HPE SMH version 2.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"2.0", test_version2:"2.2.9.3.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
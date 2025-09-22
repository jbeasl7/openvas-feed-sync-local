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
  script_oid("1.3.6.1.4.1.25623.1.0.800293");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4185");
  script_name("HP/HPE System Management Homepage (SMH) XSS Vulnerability (HPSBMA02504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=126529736830358&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38081");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509195/100/0/threaded");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c02000727");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the
  'proxy/smhui/getuiinfo' script when processing the 'servercert' parameter.");

  script_tag(name:"solution", value:"Update to version 6.0.0.96 (for Windows), 6.0.0-95 (for Linux) or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script on the user's web browser by injecting web script and steal cookie based
  authentication credentials.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 6.0 on all platforms.");

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

if( version_is_less( version:version, test_version:"6.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
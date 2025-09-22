# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:bigfix_webreports";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140070");
  script_version("2022-05-09T06:06:23+0000");
  script_tag(name:"last_modification", value:"2022-05-09 06:06:23 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2016-11-21 10:40:03 +0100 (Mon, 21 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-07 19:44:00 +0000 (Tue, 07 Feb 2017)");

  script_cve_id("CVE-2016-0396");

  script_tag(name:"qod", value:"50"); # There are Workarounds and Mitigations. Relying on the version would result in FPs...

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM BigFix Platform Remote Command Injection Vulnerability (swg21993206)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_bigfix_web_reports_http_detect.nasl");
  script_mandatory_keys("hcl/bigfix/web_reports/detected");

  script_tag(name:"summary", value:"IBM BigFix Platform is prone to a remote command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary
  commands within the context of the application.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94155");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993206");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range_exclusive( version:vers, test_version_lo:"9.0", test_version_up:"9.5.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.5.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

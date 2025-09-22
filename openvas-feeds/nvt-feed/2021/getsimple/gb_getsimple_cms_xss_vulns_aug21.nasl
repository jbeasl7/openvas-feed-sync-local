# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:get-simple:getsimple_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118156");
  script_version("2022-08-19T10:10:35+0000");
  script_tag(name:"last_modification", value:"2022-08-19 10:10:35 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"creation_date", value:"2021-08-17 15:28:12 +0200 (Tue, 17 Aug 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-19 14:05:00 +0000 (Thu, 19 Aug 2021)");

  script_cve_id("CVE-2021-36601");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix"); # Vendor does not acknowledge the issues as vulnerabilities

  script_name("GetSimple CMS <= 3.3.16 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_getsimple_cms_http_detect.nasl");
  script_mandatory_keys("getsimple_cms/detected");

  script_tag(name:"summary", value:"GetSimple CMS is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Reflected XSS leads to Remote Code Execution (RCE) in 'admin/theme.php'

  - XSS via upload in 'admin/upload.php'

  - XSS in 'admin/edit.php'

  - CVE-2021-36601: Function TSL does not filter check settings.php Website URL: 'siteURL'
  parameter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1338");
  script_xref(name:"URL", value:"https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1336");
  script_xref(name:"URL", value:"https://github.com/GetSimpleCMS/GetSimpleCMS/issues/1334");
  script_xref(name:"URL", value:"https://github.com/kk98kk0/exploit/blob/dbd10a47b0585ba4c673c952a280d502294cdbf4/GetSimpleCMS-3.3.16-xss.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"3.3.16" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

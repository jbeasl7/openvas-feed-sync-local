# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmailer_project:phpmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108468");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2008-5619");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-09-25 09:59:32 +0200 (Tue, 25 Sep 2018)");
  script_name("PHPMailer < 5.2.10 'html2text' Library RCE Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32799");
  script_xref(name:"URL", value:"https://github.com/PHPMailer/PHPMailer/blob/master/SECURITY.md");

  script_tag(name:"summary", value:"PHPMailer is prone to a remote code execution (RCE)
  vulnerability within the shipped 'html2text' library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because PHPMailer ships a vulnerable 'html2text.php Chuggnutt HTML to Text Converter'
  library which allows remote attackers to execute arbitrary code via crafted input that is processed
  by the preg_replace function with the eval switch.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code via crafted
  input.");

  script_tag(name:"affected", value:"PHPMailer versions before 5.2.10 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 5.2.10 or later and make sure to remove the
  file 'extras/class.html2text.php' from the installation.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.2.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.2.10", install_url:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
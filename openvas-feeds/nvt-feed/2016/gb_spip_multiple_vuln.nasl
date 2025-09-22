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

CPE = "cpe:/a:spip:spip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809305");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-11-08 15:15:46 +0530 (Tue, 08 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-24 01:29:00 +0000 (Wed, 24 May 2017)");


  script_cve_id("CVE-2016-7998", "CVE-2016-7999", "CVE-2016-7982", "CVE-2016-7980", "CVE-2016-7981");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("SPIP < 3.1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SPIP is prone to multiple vulnerabilities:

  - The SPIP template composer/compiler does not correctly handle SPIP 'INCLUDE/INCLURE' tags.

  - The 'var_url' parameter of the 'valider_xml' file is not correctly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server, trick an administrator to open the malicious link, retrieve arbitrary
  files, bypass security restrictions and possibly have other unknown impact on the target
  system.");

  script_tag(name:"affected", value:"SPIP version prior to 3.1.3.");

  script_tag(name:"solution", value:"Update to version 3.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93451");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40596");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40597");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Oct/78");
  script_xref(name:"URL", value:"http://osdir.com/ml/opensource-software-security/2016-10/msg00108.html");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version:version, test_version:"3.1.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.1.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:manageengine_supportcenter_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805807");
  script_version("2021-12-01T12:10:25+0000");
  script_tag(name:"last_modification", value:"2021-12-01 12:10:25 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2015-06-25 12:35:38 +0530 (Thu, 25 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2015-5149", "CVE-2015-5150");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine SupportCenter Plus Multiple Vulnerabilities (Jun 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_supportcenter_plus_http_detect.nasl");
  script_mandatory_keys("manageengine/supportcenter_plus/detected");

  script_tag(name:"summary", value:"ManageEngine SupportCenter Plus is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Missing user access control mechanisms

  - 'module' parameter to /workorder/Attachment.jsp?component=Request is not properly sanitized to
  check '../' characters

  - 'query' and 'compAcct' parameters are not properly sanitized before passing to
  /jsp/ResetADPwd.jsp and jsp/CacheScreenWidth.jsp scripts");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  HTML or script code, upload arbitrary files and bypass access restrictions.");

  script_tag(name:"affected", value:"ManageEngine SupportCenter Plus build 7900 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37322");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/download_content.php?id=1501");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7900")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
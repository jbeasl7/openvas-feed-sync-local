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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812576");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2018-8722");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-06 12:55:00 +0000 (Fri, 06 Apr 2018)");
  script_tag(name:"creation_date", value:"2018-03-21 10:15:02 +0530 (Wed, 21 Mar 2018)");

  script_name("ManageEngine Desktop Central <= 9.1.099 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"ManageEngine Desktop Central is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw allows to inject client-side script into Desktop
  Centrals web page.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central version 9.1.099 and prior.");

  script_tag(name:"solution", value:"Update to version 9.2.026 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/desktop-central/cross-site-scripting-vulnerability.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103426");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_http_detect.nasl");
  script_mandatory_keys("manageengine/desktop_central/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less_equal(version:vers, test_version:"9.1.099")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.2.026", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
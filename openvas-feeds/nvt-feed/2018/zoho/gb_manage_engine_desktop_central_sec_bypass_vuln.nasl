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
  script_oid("1.3.6.1.4.1.25623.1.0.812521");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2014-7862");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:53:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-02-23 15:47:34 +0530 (Fri, 23 Feb 2018)");

  script_name("ManageEngine Desktop Central < 9.0.109 Remote Security Bypass Vulnerability");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_http_detect.nasl");
  script_mandatory_keys("manageengine/desktop_central/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/archive/1/534356/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71849");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/desktop-central/cve20147862-unauthorized-account-creation.html");

  script_tag(name:"summary", value:"ManageEngine Desktop Central is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in 'DCPluginServelet' while creating the
  administrator account.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security
  restrictions and perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central/MSP before version 9.0.109.");

  script_tag(name:"solution", value:"Update to version 9.0.109 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if (version_is_less(version:vers, test_version:"9.0.109")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.0.109", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:enalean:tuleap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106910");
  script_version("2021-10-19T05:42:00+0000");
  script_tag(name:"last_modification", value:"2021-10-19 05:42:00 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2017-06-28 08:25:42 +0700 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-7981");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tuleap < 9.7 Remote OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tuleap_http_detect.nasl");
  script_mandatory_keys("tuleap/detected");

  script_tag(name:"summary", value:"Tuleap allows command injection via the PhpWiki
  SyntaxHighlighter plugin.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote command execution is achieved by entering a
  SyntaxHighlighter plugin directive in a new wiki page on any wiki available in any project. The
  SyntaxHighligter plugin in vulnerable versions of PHPWiki passes the 'syntax' argument to the
  'proc_open()' PHP builtin function which spawns a process in the operating system running the web
  application.");

  script_tag(name:"impact", value:"Authenticated users, including unprivileged users, with access
  to a project containing a wiki, can exploit this command injection vulnerability to gain remote
  unauthorised access to the server hosting the Tuleap web application.");

  script_tag(name:"affected", value:"Tuleap version 8.3 through 9.6.99.86.");

  script_tag(name:"solution", value:"Update to version 9.7 or later.");

  script_xref(name:"URL", value:"https://tuleap.net/plugins/tracker/?aid=10159");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "8.3", test_version2: "9.6.99.86")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
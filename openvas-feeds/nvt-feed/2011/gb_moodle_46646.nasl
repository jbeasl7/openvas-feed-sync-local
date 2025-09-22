# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:moodle:moodle";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103103");
  script_version("2022-07-22T10:11:18+0000");
  script_tag(name:"last_modification", value:"2022-07-22 10:11:18 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Moodle Prior 1.9.x < 1.9.11, 2.0.x < 2.0.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46646");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170002");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170003");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170004");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170006");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170008");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170009");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170010");
  script_xref(name:"URL", value:"http://moodle.org/mod/forum/discuss.php?d=170011");
  script_xref(name:"URL", value:"http://moodle.org/security/");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - multiple cross-site scripting issues

  - multiple information-disclosure issues

  - an HTML-injection issue

  - an insecure permissions issue");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions, obtain sensitive information, perform unauthorized actions, and compromise the
  application. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Moodle versions 1.9.x prior to 1.9.11 and 2.0.x prior to
  2.0.2.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.0.0",test_version2:"2.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.0.2");
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.9",test_version2:"1.9.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.9.11");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

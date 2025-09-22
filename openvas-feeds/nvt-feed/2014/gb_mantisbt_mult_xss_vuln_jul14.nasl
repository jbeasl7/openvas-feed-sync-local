# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804676");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2013-1810", "CVE-2013-0197");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-07-14 11:59:38 +0530 (Mon, 14 Jul 2014)");

  script_name("MantisBT < 1.2.13 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"MantisBT is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed via the 'name' parameter to manage_proj_cat_add.php script when
creating a category is not properly sanitised in core/summary_api.php script
before being used.

  - Input passed to the 'match_type' POST parameter in bugs/search.php script is
not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser and
the server.");

  script_tag(name:"affected", value:"MantisBT version 1.2.12, prior versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 1.2.13 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57468");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81394");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=15384");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=15373");
  script_xref(name:"URL", value:"http://hauntit.blogspot.de/2013/01/en-mantis-bug-tracker-1212-persistent.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mantisbt_http_detect.nasl");
  script_mandatory_keys("mantisbt/detected");

  script_tag(name:"solution_type", value:"VendorFix");

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

if (version_is_less_equal(version: version, test_version: "1.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

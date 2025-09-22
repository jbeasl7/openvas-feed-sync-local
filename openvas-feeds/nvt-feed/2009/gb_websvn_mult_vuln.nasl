# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:tigris:websvn";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900441");
  script_version("2022-04-01T05:47:35+0000");
  script_tag(name:"last_modification", value:"2022-04-01 05:47:35 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-5918", "CVE-2008-5919", "CVE-2008-5920", "CVE-2009-0240");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WebSVN < 2.1.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_websvn_http_detect.nasl");
  script_mandatory_keys("websvn/detected");

  script_tag(name:"summary", value:"WebSVN is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - input passed in the URL to index.php is not properly sanitised before being returned to the
  user.

  - input passed to the rev parameter in rss.php is not properly sanitised before being used, when
  magic_quotes_gpc is disable.

  - restricted access to the repositories is not properly enforced.");

  script_tag(name:"impact", value:"Successful exploitation may let the attacker execute arbitrary
  code in the context of the web application, execute cross-site scripting attacks or gain
  sensitive information.");

  script_tag(name:"affected", value:"WebSVN version prior to version 2.1.0.");

  script_tag(name:"solution", value:"Update to version 2.1.0 or later.");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6822");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512191");

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

if (version_is_less(version: version, test_version: "2.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:gtranslate:translate_wordpress_with_gtranslate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124049");
  script_version("2023-01-13T10:21:10+0000");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-03-31 19:46:46 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 18:55:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2022-0770");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GTranslate Plugin < 2.9.9 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gtranslate/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GTranslate' is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF checks in some files, and writes
  debug data such as user's cookies in a publicly accessible file if a specific parameter is used when
  requesting them. Combining those two issues, an attacker could gain access to a logged in admin
  cookies by making them open a malicious link or page");

  script_tag(name:"affected", value:"WordPress GTranslate plugin prior to version 2.9.9.");

  script_tag(name:"solution", value:"Update to version 2.9.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/49abe79c-ab1c-4dbf-824c-8daaac7e079d");

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

if (version_is_less(version: version, test_version: "2.9.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

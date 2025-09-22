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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811784");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2017-14718", "CVE-2017-14719", "CVE-2017-14720", "CVE-2017-14721",
                "CVE-2017-14722", "CVE-2017-14723", "CVE-2017-14724", "CVE-2017-14725",
                "CVE-2017-14726");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-10 02:29:00 +0000 (Fri, 10 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-09-21 12:41:39 +0530 (Thu, 21 Sep 2017)");
  script_name("WordPress < 4.8.2 Multiple Vulnerabilities - Linux");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://wordpress.org/documentation/wordpress-version/version-4-8-2/");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/09/wordpress-4-8-2-security-and-maintenance-release/");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-14718: A cross-site scripting (XSS) vulnerability was discovered in the link modal.

  - CVE-2017-14719: A path traversal vulnerability was discovered in the file unzipping code.

  - CVE-2017-14720: A cross-site scripting (XSS) vulnerability was discovered in template names.

  - CVE-2017-14721: A cross-site scripting (XSS) vulnerability was discovered in the plugin editor.

  - CVE-2017-14722: A path traversal vulnerability was discovered in the customizer.

  - CVE-2017-14723: $wpdb->prepare() can create unexpected and unsafe queries leading to potential
  SQL injection (SQLi). WordPress core is not directly vulnerable to this issue, but hardening was
  added to prevent plugins and themes from accidentally causing a vulnerability.

  - CVE-2017-14724: A cross-site scripting (XSS) vulnerability was discovered in the oEmbed
  discovery.

  - CVE-2017-14725: An open redirect was discovered on the user and term edit screens.

  - CVE-2017-14726: A cross-site scripting (XSS) vulnerability was discovered in the visual
  editor.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  XSS, SQLi, directory traversal and open redirect attacks.");

  script_tag(name:"affected", value:"WordPress versions 4.8.1 and earlier.");

  script_tag(name:"solution", value:"Update to version 4.8.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if (version_is_less(version: version, test_version: "4.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

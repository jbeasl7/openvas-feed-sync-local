# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

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
  script_oid("1.3.6.1.4.1.25623.1.0.812507");
  script_version("2023-03-01T10:20:05+0000");
  script_cve_id("CVE-2018-5776");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-01 15:06:00 +0000 (Thu, 01 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-01-22 14:09:01 +0530 (Mon, 22 Jan 2018)");
  script_name("WordPress Multiple Vulnerabilities (Jan 2018) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS flaw exists in the Flash fallback
  files in MediaElement, a library that is included with WordPress. Because
  the Flash files are no longer needed for most use cases, they have been
  removed from WordPress.

  21 other bugs were fixed in WordPress 4.9.2:

  - JavaScript errors that prevented saving posts in Firefox have been fixed.

  - The previous taxonomy-agnostic behavior of get_category_link() and
    category_description() was restored.

  - Switching themes will now attempt to restore previous widget assignments,
    even when there are no sidebars to map.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross site scripting attacks.");

  script_tag(name:"affected", value:"WordPress versions prior to 4.9.2.");

  script_tag(name:"solution", value:"Update to WordPress version 4.9.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/news/2018/01/wordpress-4-9-2-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://codex.wordpress.org/Version_4.9.2");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"4.9.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.9.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
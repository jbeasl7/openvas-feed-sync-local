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

CPE = "cpe:/a:gogs:gogs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141678");
  script_version("2022-03-23T12:27:29+0000");
  script_tag(name:"last_modification", value:"2022-03-23 12:27:29 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"creation_date", value:"2018-11-13 12:10:41 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-29 18:07:00 +0000 (Tue, 29 Jan 2019)");

  script_cve_id("CVE-2018-18925");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gogs < 0.11.79 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-18925: Gogs allows remote code execution because it does not properly validate session
  IDs, as demonstrated by a '..' session-file forgery in the file session provider in file.go. This
  is related to session ID handling in the go-macaron/session code for Macaron.

  - No CVE: Critical CSRF vulnerabilities on API routes

  - No CVE: Log out only deletes browser cookies

  - No CVE: Some routes need to be POST

  - No CVE: Stored XSS in external issue tracker URL format");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Gogs prior to version 0.11.79.");

  script_tag(name:"solution", value:"Update to version 0.11.79 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/releases/tag/v0.11.79");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5469");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5355");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5540");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5541");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/5545");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.11.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.11.79");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

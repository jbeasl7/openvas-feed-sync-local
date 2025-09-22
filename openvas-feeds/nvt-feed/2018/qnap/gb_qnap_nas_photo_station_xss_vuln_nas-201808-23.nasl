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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112366");
  script_version("2022-05-25T12:20:12+0000");
  script_cve_id("CVE-2017-0715");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-25 12:20:12 +0000 (Wed, 25 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-08-28 13:11:11 +0200 (Tue, 28 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("QNAP NAS Photo Station XSS Vulnerability (nas-201808-23)");

  script_tag(name:"summary", value:"QNAP NAS Photo Station is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient sanitization
  of user supplied input.");

  script_tag(name:"impact", value:"If successfully exploited, the vulnerability could
  allow remote attackers to inject Javascript code into the compromised application.");

  script_tag(name:"affected", value:"QNAP Photo Station versions through 5.7.0.");

  script_tag(name:"solution", value:"Update to version 5.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201808-23");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/PhotoStation/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:qnap:photo_station";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.1");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);

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

CPE = "cpe:/a:qnap:music_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141489");
  script_version("2021-05-27T06:00:15+0200");
  script_tag(name:"last_modification", value:"2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2018-09-18 15:13:19 +0700 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-0718");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Music Station < 5.1.3 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_musicstation_detect.nasl");
  script_mandatory_keys("qnap_musicstation/detected");

  script_tag(name:"summary", value:"QNAP QTS Music Station is prone to a command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"impact", value:"The command injection vulnerability could allow remote
  attackers to run arbitrary commands in the compromised application.");

  script_tag(name:"affected", value:"QNAP QTS Music Station 5.1.2 and earlier.");

  script_tag(name:"solution", value:"Update to version 5.1.3 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201809-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

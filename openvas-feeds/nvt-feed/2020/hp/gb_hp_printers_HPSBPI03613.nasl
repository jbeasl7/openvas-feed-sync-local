# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:hp:deskjet_3630_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143348");
  script_version("2022-02-15T10:35:00+0000");
  script_tag(name:"last_modification", value:"2022-02-15 10:35:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2020-01-13 06:26:25 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-22 18:29:00 +0000 (Wed, 22 Jan 2020)");

  script_cve_id("CVE-2019-6319", "CVE-2019-6320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP DeskJet 3630 Printers CSRF Vulnerability (HPSBPI03613)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Certain HP DeskJet 3630 All-in-One Printers have a cross-site
  request forgery (CSRF) vulnerability that could lead to a denial of service (DOS) or device
  misconfiguration.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP DeskJet 3630 All-in-One Printers.");

  script_tag(name:"solution", value:"Update to firmware version SWP1FN1912BR or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06308143");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (version_is_less(version: version, test_version: "SWP1FN1912BR")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "SWP1FN1912BR");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

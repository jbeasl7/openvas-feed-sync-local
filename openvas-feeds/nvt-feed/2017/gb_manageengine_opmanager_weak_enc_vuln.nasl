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

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140279");
  script_version("2021-09-22T15:39:37+0000");
  script_tag(name:"last_modification", value:"2021-09-22 15:39:37 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-08-07 16:08:23 +0700 (Mon, 07 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 18:36:00 +0000 (Tue, 15 Aug 2017)");

  script_cve_id("CVE-2015-9107");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine OpManager 11 - 12.2 Weak Encryption Algorithm Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl");
  script_mandatory_keys("manageengine/opmanager/detected");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to a weak encryption algorithm
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ManageEngine OpManager uses a custom encryption algorithm to
  protect the credential used to access the monitored devices. The implemented algorithm doesn't use
  a per-system key or even a salt. Therefore, it's possible to create a universal decryptor.");

  script_tag(name:"affected", value:"ManageEngine OpManager version 11 through 12.2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://github.com/theguly/DecryptOpManager");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "11", test_version2: "12.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None available", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117236");
  script_version("2022-05-30T09:32:02+0000");
  script_tag(name:"last_modification", value:"2022-05-30 09:32:02 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2021-03-01 13:55:12 +0000 (Mon, 01 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-17 17:42:00 +0000 (Wed, 17 Mar 2021)");

  script_cve_id("CVE-2021-3310");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.10.122 Multiple Vulnerabilities (WDC-21002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone
  to a local code execution and information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The vulnerability allowed AFP and SMB shares to follow
  symbolic links. This could potentially allow an attacker to execute malicious code on
  the user's device and thereby take over the system. It also allowed an attacker to read
  data and files on the system such as the /etc/shadow file.

  The local code execution vulnerability was resolved by not allowing symbolic links to be
  followed on SMB and AFP shares. Permission changes were also made to the /etc/shadow
  file to prevent unprivileged users from accessing it.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100,
  My Cloud EX2 Ultra, My Cloud EX2100, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud
  DL2100, My Cloud DL4100 and My Cloud (P/N: WDBCTLxxxxxx-10) with firmware versions
  prior to 5.10.122.");

  script_tag(name:"solution", value:"Update to firmware version 5.10.122 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/productsecurity/wdc-21002-my-cloud-firmware-version-5-10-122");
  script_xref(name:"URL", value:"https://community.wd.com/t/my-cloud-os-5-firmware-release-note-v5-10-122/264016");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.09.115")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.10.122");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

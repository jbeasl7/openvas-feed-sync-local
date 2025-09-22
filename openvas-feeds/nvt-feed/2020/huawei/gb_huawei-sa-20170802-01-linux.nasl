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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108776");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:32:00 +0000 (Fri, 24 Feb 2023)");

  script_cve_id("CVE-2017-8890", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: 'Phoenix Talon' Vulnerabilities in Linux Kernel (huawei-sa-20170802-01-linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"The Linux operating system has four security vulnerabilities called 'Phoenix Talon', which affect Linux kernel 2.5.69 to Linux kernel 4.11.");

  script_tag(name:"insight", value:"The Linux operating system has four security vulnerabilities called 'Phoenix Talon', which affect Linux kernel 2.5.69 to Linux kernel 4.11. Successful exploit of these vulnerabilities can allow an attacker to launch DOS attacks and can lead to arbitrary code execution when certain conditions are met. (Vulnerability ID: HWPSIRT-2017-06165, HWPSIRT-2017-07130, HWPSIRT-2017-07131 and HWPSIRT-2017-07132)The four vulnerabilities have been assigned four Common Vulnerabilities and Exposures (CVE) IDs: CVE-2017-8890, CVE-2017-9075, CVE-2017-9076 and CVE-2017-9077.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit of this vulnerability can allow an attacker to launch DOS attacks and can lead to arbitrary code execution when certain conditions are met.");

  script_tag(name:"affected", value:"AP5010DN-AGN-FAT versions V200R005C10

  AP5010SN-GN versions V200R005C10 V200R006C00 V200R006C10

  AP5010SN-GN-FAT versions V200R005C10

  AT815SN versions V200R005C10 V200R006C00 V200R006C10

  HiSTBAndroid versions HiSTBAndroidV600R001C00SPC061");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170802-01-linux-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ap5010dn-agn-fat_firmware",
                     "cpe:/o:huawei:ap5010sn-gn_firmware",
                     "cpe:/o:huawei:ap5010sn-gn-fat_firmware",
                     "cpe:/o:huawei:at815sn_firmware",
                     "cpe:/o:huawei:histbandroid_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ap5010dn-agn-fat_firmware")  {
  if(version =~ "^V200R005C10") {
    if (!patch || version_is_less(version: patch, test_version: "v2r7c20spc300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v2r7c20spc300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap5010sn-gn_firmware")  {
  if(version =~ "^V200R005C10" || version =~ "^V200R006C00" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "v2r7c20spc300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v2r7c20spc300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap5010sn-gn-fat_firmware")  {
  if(version =~ "^V200R005C10") {
    if (!patch || version_is_less(version: patch, test_version: "v2r7c20spc300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v2r7c20spc300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:at815sn_firmware")  {
  if(version =~ "^V200R005C10" || version =~ "^V200R006C00" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V2R7C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R7C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:histbandroid_firmware")  {
  if(version =~ "^V600R001C00SPC061") {
    if (!patch || version_is_less(version: patch, test_version: "V600R001C00SPC066")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R001C00SPC066");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

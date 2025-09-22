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
  script_oid("1.3.6.1.4.1.25623.1.0.108773");
  script_version("2022-09-05T10:11:01+0000");
  script_tag(name:"last_modification", value:"2022-09-05 10:11:01 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 16:25:00 +0000 (Thu, 01 Sep 2022)");

  script_cve_id("CVE-2016-7055");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: OpenSSL Montgomery multiplication may produce incorrect results Vulnerability (huawei-sa-20170419-01-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a carry propagating bug in the Broadwell-specific Montgomery multiplication procedure that handles input lengths divisible by, but longer than 256 bits.");

  script_tag(name:"insight", value:"There is a carry propagating bug in the Broadwell-specific Montgomery multiplication procedure that handles input lengths divisible by, but longer than 256 bits. and may produce incorrect results. (Vulnerability ID: HWPSIRT-2016-11044)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-7055.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploitation of the vulnerability allows producing incorrect results.");

  script_tag(name:"affected", value:"AP5030DN versions V200R007C00SPC100 V200R007C10 V200R007C10SPC100 V200R007C10SPC200

TE60 versions V600R006C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170419-01-openssl-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:9032_firmware",
                     "cpe:/o:huawei:ap5030dn_firmware",
                     "cpe:/o:huawei:ap8000_firmware",
                     "cpe:/o:huawei:e9000_chassis_firmware",
                     "cpe:/o:huawei:oceanstor_backup_firmware",
                     "cpe:/o:huawei:te60_firmware",
                     "cpe:/o:huawei:esdk_platform_firmware",
                     "cpe:/o:huawei:esight_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:9032_firmware")  {
  if(version =~ "^V100R001C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R001C20SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R001C20SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap5030dn_firmware")  {
  if(version =~ "^V200R007C00SPC100" || version =~ "^V200R007C10" || version =~ "^V200R007C10SPC100" || version =~ "^V200R007C10SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V2R7C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R7C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap8000_firmware")  {
  if(version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R00R008C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R00R008C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:e9000_chassis_firmware")  {
  if(version =~ "^V100R001C10SPC236" || version =~ "^V100R001C10SPC236T") {
    if (!patch || version_is_less(version: patch, test_version: "V100R001C00SPC310")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R001C00SPC310");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:oceanstor_backup_firmware")  {
  if(version =~ "^V200R001C00" || version =~ "^V200R001C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V2R1C00SPC203")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R1C00SPC203");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te60_firmware")  {
  if(version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:esdk_platform_firmware")  {
  if(version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R001C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R001C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:esight_firmware")  {
  if(version =~ "^V300R002C01") {
    if (!patch || version_is_less(version: patch, test_version: "V300R006C00SPC211")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V300R006C00SPC211");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);


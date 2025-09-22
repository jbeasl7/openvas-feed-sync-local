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
  script_oid("1.3.6.1.4.1.25623.1.0.143987");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-27 05:22:38 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-09 14:39:00 +0000 (Fri, 09 Mar 2018)");

  script_cve_id("CVE-2017-17295", "CVE-2017-17296", "CVE-2017-17297");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple Vulnerabilities in Some Huawei Products (huawei-sa-20171215-01-buffer)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There are two buffer overflow vulnerabilities in some Huawei products.");

  script_tag(name:"insight", value:"There are two buffer overflow vulnerabilities in some Huawei products. An unauthenticated, remote attacker may send specially crafted SIP packages to the affected products. Due to the insufficient validation of some values for SIP packages, successful exploit may cause services abnormal. (Vulnerability ID: HWPSIRT-2017-04098 and HWPSIRT-2017-04100)The two vulnerabilities have been assigned two Common Vulnerabilities and Exposures (CVE) IDs: CVE-2017-17295 and CVE-2017-17297.There is a memory leak vulnerability in some Huawei products. An unauthenticated, remote attacker may send specially crafted H323 packages to the affected products. Due to not release the allocated memory properly to handle the packets, successful exploit may cause memory leak and some services abnormal. (Vulnerability ID: HWPSIRT-2017-04099)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17296.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause services abnormal.");

  script_tag(name:"affected", value:"AR120-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR1200 versions V200R006C10 V200R006C13 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR1200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR150 versions V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR150-S versions V200R006C10SPC300 V200R007C00 V200R008C20 V200R008C30

  AR160 versions V200R006C10 V200R006C12 V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR200 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20 V200R008C30

  AR200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR2200 versions V200R006C10 V200R006C13 V200R006C16PWE V200R007C00 V200R007C01 V200R007C02 V200R008C20 V200R008C30

  AR2200-S versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  AR3200 versions V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

  AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20

  AR510 versions V200R006C10 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC180T V200R008C20 V200R008C30

  DP300 versions V500R002C00

  IPS Module versions V100R001C10SPC200 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NGFW Module versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20 V500R002C00 V500R002C10

  NIP6300 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NIP6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

  NIP6800 versions V500R001C50

  NetEngine16EX versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  RP200 versions V500R002C00SPC200 V600R006C00

  RSE6500 versions V500R002C00

  SRG1300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

  SRG2300 versions V200R006C10 V200R007C00 V200R007C02 V200R008C20 V200R008C30

  SRG3300 versions V200R006C10 V200R007C00 V200R008C20 V200R008C30

  SVN5600 versions V200R003C00SPC100 V200R003C10

  SVN5800 versions V200R003C10

  SVN5800-C versions V200R003C00SPC100 V200R003C10

  SeMG9811 versions V300R001C01SPC500

  Secospace USG6300 versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  Secospace USG6500 versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  Secospace USG6600 versions V100R001C00SPC200 V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

  TE30 versions V100R001C02B053SP02 V100R001C10 V500R002C00SPC200 V600R006C00

  TE40 versions V500R002C00SPC600 V600R006C00

  TE50 versions V500R002C00SPC600 V600R006C00

  TE60 versions V100R001C01SPC100 V100R001C10 V500R002C00 V600R006C00

  TP3106 versions V100R002C00

  TP3206 versions V100R002C00 V100R002C10

  USG9500 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

  USG9520 versions V300R001C01SPC500 V300R001C20SPC200

  USG9560 versions V300R001C01SPC500 V300R001C20SPC200

  USG9580 versions V300R001C01SPC500 V300R001C20SPC200

  ViewPoint 9030 versions V100R011C02SPC100 V100R011C03B012SP15

  eSpace U1981 versions V200R003C20SPC900 V200R003C30SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171215-01-buffer-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar150-s_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:ar510_firmware",
                     "cpe:/o:huawei:dp300_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:nip6800_firmware",
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:rp200_firmware",
                     "cpe:/o:huawei:rse6500_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:svn5600_firmware",
                     "cpe:/o:huawei:svn5800_firmware",
                     "cpe:/o:huawei:svn5800-c_firmware",
                     "cpe:/o:huawei:semg9811_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:te30_firmware",
                     "cpe:/o:huawei:te40_firmware",
                     "cpe:/o:huawei:te50_firmware",
                     "cpe:/o:huawei:te60_firmware",
                     "cpe:/o:huawei:tp3106_firmware",
                     "cpe:/o:huawei:tp3206_firmware",
                     "cpe:/o:huawei:usg9500_firmware",
                     "cpe:/o:huawei:usg9520_firmware",
                     "cpe:/o:huawei:usg9560_firmware",
                     "cpe:/o:huawei:usg9580_firmware",
                     "cpe:/o:huawei:viewpoint_9030_firmware",
                     "cpe:/o:huawei:espace_u1981_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C13" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C12" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C13" || version =~ "^V200R006C16PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C11" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C00" || version =~ "^V200R008C10" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar510_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C12" || version =~ "^V200R006C13" || version =~ "^V200R006C15" || version =~ "^V200R006C16" || version =~ "^V200R006C17" || version =~ "^V200R007C00SPC180T" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:dp300_firmware")  {
  if(version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version =~ "^V100R001C10SPC200" || version =~ "^V100R001C30" || version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V100R001C10SPC200" || version =~ "^V100R001C20SPC100" || version =~ "^V100R001C30" || version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R002C00" || version =~ "^V500R002C10") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6800_firmware")  {
  if(version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:rp200_firmware")  {
  if(version =~ "^V500R002C00SPC200" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:rse6500_firmware")  {
  if(version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5600_firmware")  {
  if(version =~ "^V200R003C00SPC100" || version =~ "^V200R003C10") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5800_firmware")  {
  if(version =~ "^V200R003C10") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:svn5800-c_firmware")  {
  if(version =~ "^V200R003C00SPC100" || version =~ "^V200R003C10") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:semg9811_firmware")  {
  if(version =~ "^V300R001C01SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V100R001C10SPC200" || version =~ "^V100R001C20SPC100" || version =~ "^V100R001C30B018" || version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version =~ "^V100R001C10SPC200" || version =~ "^V100R001C20SPC100" || version =~ "^V100R001C30B018" || version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V100R001C00SPC200" || version =~ "^V100R001C10SPC200" || version =~ "^V100R001C20SPC100" || version =~ "^V100R001C30" || version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te30_firmware")  {
  if(version =~ "^V100R001C02B053SP02" || version =~ "^V100R001C10" || version =~ "^V500R002C00SPC200" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te40_firmware")  {
  if(version =~ "^V500R002C00SPC600" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te50_firmware")  {
  if(version =~ "^V500R002C00SPC600" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te60_firmware")  {
  if(version =~ "^V100R001C01SPC100" || version =~ "^V100R001C10" || version =~ "^V500R002C00" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC400")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC400");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:tp3106_firmware")  {
  if(version =~ "^V100R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:tp3206_firmware")  {
  if(version =~ "^V100R002C00" || version =~ "^V100R002C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" || version =~ "^V500R001C50") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9520_firmware")  {
  if(version =~ "^V300R001C01SPC500" || version =~ "^V300R001C20SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9560_firmware")  {
  if(version =~ "^V300R001C01SPC500" || version =~ "^V300R001C20SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9580_firmware")  {
  if(version =~ "^V300R001C01SPC500" || version =~ "^V300R001C20SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:viewpoint_9030_firmware")  {
  if(version =~ "^V100R011C02SPC100" || version =~ "^V100R011C03B012SP15") {
    if (!patch || version_is_less(version: patch, test_version: "V100R011C03SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R011C03SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_u1981_firmware")  {
  if(version =~ "^V200R003C20SPC900" || version =~ "^V200R003C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003C30SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003C30SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

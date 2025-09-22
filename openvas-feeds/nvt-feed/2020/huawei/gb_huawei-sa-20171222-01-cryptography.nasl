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
  script_oid("1.3.6.1.4.1.25623.1.0.143993");
  script_version("2021-08-03T02:00:56+0000");
  script_tag(name:"last_modification", value:"2021-08-03 02:00:56 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-27 08:54:30 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-17301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Cryptography Vulnerability in Some Huawei Products (huawei-sa-20171222-01-cryptography)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a weak cryptography vulnerability.");

  script_tag(name:"insight", value:"Some Huawei products have a weak cryptography vulnerability. Due to not properly some values in the certificates, an unauthenticated remote attacker could forges a specific RSA certificate and exploits the vulnerability to pass identity authentication and logs into the target device to obtain permissions configured for the specific user name. (Vulnerability ID: HWPSIRT-2016-09014)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17301.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker may exploit the vulnerability to forge a specific RSA certificate and log into the target device to obtain permissions configured for the specific user name.");

  script_tag(name:"affected", value:"AR120-S versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

AR1200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20

AR1200-S versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

AR150 versions V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20

AR160 versions V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20

AR200 versions V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R008C20

AR200-S versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

AR2200 versions V200R005C20 V200R005C32 V200R006C10 V200R007C00 V200R007C01 V200R007C02 V200R008C20

AR2200-S versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

AR3200 versions V200R005C32 V200R006C10 V200R006C11 V200R007C00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C30

AR3600 versions V200R006C10 V200R007C00 V200R007C01 V200R008C20

AR510 versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

CloudEngine 12800 versions V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00 V200R001C00

CloudEngine 5800 versions V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00 V200R001C00

CloudEngine 6800 versions V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00 V200R001C00

CloudEngine 7800 versions V100R003C00 V100R003C10 V100R005C00 V100R005C10 V100R006C00 V200R001C00

DBS3900 TDD LTE versions V100R004C10

DP300 versions V500R002C00

SMC2.0 versions V100R003C10 V100R005C00 V500R002C00

SRG1300 versions V200R005C32 V200R006C10 V200R007C00 V200R007C02 V200R008C20

SRG2300 versions V200R005C32 V200R006C10 V200R007C00 V200R007C02 V200R008C20

SRG3300 versions V200R005C32 V200R006C10 V200R007C00 V200R008C20

Secospace USG6300 versions V500R001C30SPC100 V500R001C30SPC200 V500R001C30SPC600

Secospace USG6500 versions V500R001C30SPC100 V500R001C30SPC200 V500R001C30SPC600

Secospace USG6600 versions V500R001C30SPC100 V500R001C30SPC200 V500R001C30SPC600

TE30 versions V100R001C10

TE60 versions V100R003C00 V500R002C00

USG9500 versions V500R001C30SPC100 V500R001C30SPC200 V500R001C30SPC600

VP9660 versions V200R001C02 V200R001C30 V500R002C00

ViewPoint 8660 versions V100R008C02 V100R008C03

eSpace IAD versions V300R002C01SPC500B010

eSpace U1981 versions V200R003C20SPH103B010 V200R003C30B015

eSpace USM versions V100R001C01 V300R001C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171222-01-cryptography-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120-s_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar1200-s_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar200-s_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar2200-s_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:ar510_firmware",
                     "cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:dbs3900_tdd_lte_firmware",
                     "cpe:/o:huawei:dp300_firmware",
                     "cpe:/o:huawei:smc2.0_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:secospace_usg6300_firmware",
                     "cpe:/o:huawei:secospace_usg6500_firmware",
                     "cpe:/o:huawei:secospace_usg6600_firmware",
                     "cpe:/o:huawei:te30_firmware",
                     "cpe:/o:huawei:te60_firmware",
                     "cpe:/o:huawei:usg9500_firmware",
                     "cpe:/o:huawei:vp9660_firmware",
                     "cpe:/o:huawei:viewpoint_8660_firmware",
                     "cpe:/o:huawei:espace_iad_firmware",
                     "cpe:/o:huawei:espace_u1981_firmware",
                     "cpe:/o:huawei:espace_usm_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R006C11" || version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C00" || version =~ "^V200R008C10" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
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
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:dbs3900_tdd_lte_firmware")  {
  if(version =~ "^V100R004C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R004C10SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R004C10SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:dp300_firmware")  {
  if(version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPCa00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCa00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:smc2.0_firmware")  {
  if(version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R007C02" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R005C32" || version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:secospace_usg6300_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:secospace_usg6500_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:secospace_usg6600_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te30_firmware")  {
  if(version =~ "^V100R001C10") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te60_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:vp9660_firmware")  {
  if(version =~ "^V200R001C02" || version =~ "^V200R001C30" || version =~ "^V500R002C00") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C10SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C10SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:viewpoint_8660_firmware")  {
  if(version =~ "^V100R008C02" || version =~ "^V100R008C03") {
    if (!patch || version_is_less(version: patch, test_version: "V100R008C03SPCc00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R008C03SPCc00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_iad_firmware")  {
  if(version =~ "^V300R002C01SPC500B010") {
    if (!patch || version_is_less(version: patch, test_version: "V300R002C01SPCm00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V300R002C01SPCm00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_u1981_firmware")  {
  if(version =~ "^V200R003C20SPH103B010" || version =~ "^V200R003C30B015") {
    if (!patch || version_is_less(version: patch, test_version: "V200R003C30SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R003C30SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_usm_firmware")  {
  if(version =~ "^V100R001C01" || version =~ "^V300R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V300R001C00SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V300R001C00SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

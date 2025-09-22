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
  script_oid("1.3.6.1.4.1.25623.1.0.143979");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 08:06:13 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 15:29:00 +0000 (Tue, 27 Mar 2018)");

  script_cve_id("CVE-2017-17135", "CVE-2017-17136", "CVE-2017-17137", "CVE-2017-17138");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple Vulnerabilities of PEM Module in Some Huawei Products (huawei-sa-20171206-01-pem)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a null pointer reference vulnerability in PEM module of Huawei products due to insufficient verification.");

  script_tag(name:"insight", value:"There is a null pointer reference vulnerability in PEM module of Huawei products due to insufficient verification. An authenticated local attacker calls PEM decoder with special parameter, which could cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06047)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17135.There is a heap overflow vulnerability in PEM module of Huawei products due to insufficient verification. An authenticated local attacker can make processing crash by a malicious certificate. The attacker can exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06048)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17136.There is an Out-of-Bounds memory access vulnerability in PEM module of Huawei products due to insufficient verification. An authenticated local attacker can make processing crash by a malicious certificate. The attacker can exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06049)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17137.There is a DoS vulnerability in PEM module of Huawei products due to insufficient verification. An authenticated local attacker can make processing into deadloop by a malicious certificate.The attacker can exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06050)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17138.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"The attacker can exploit these vulnerabilities to cause a denial of service.");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

  DP300 versions V500R002C00

  IPS Module versions V500R001C00 V500R001C30SPC100

  NGFW Module versions V500R001C00 V500R002C00SPC100

  NIP6300 versions V500R001C00 V500R001C30SPC100

  NIP6600 versions V500R001C00 V500R001C30SPC100

  RP200 versions V500R002C00SPC200 V600R006C00

  S12700 versions V200R007C00 V200R007C01 V200R008C00 V200R009C00 V200R010C00

  S1700 versions V200R006C10SPC100 V200R009C00SPC200 V200R010C00

  S2700 versions V200R006C10 V200R007C00 V200R008C00 V200R009C00 V200R010C00

  S5700 versions V200R006C00SPC100 V200R007C00 V200R008C00 V200R009C00 V200R010C00

  S6700 versions V200R008C00 V200R009C00 V200R010C00

  S7700 versions V200R007C00 V200R008C00 V200R009C00 V200R010C00

  S9700 versions V200R007C00 V200R007C01 V200R008C00 V200R009C00 V200R010C00

  Secospace USG6300 versions V500R001C00 V500R001C30SPC100

  Secospace USG6500 versions V500R001C00 V500R001C30SPC100

  Secospace USG6600 versions V500R001C00 V500R001C30SPC100

  TE30 versions V100R001C02SPC100 V100R001C10 V500R002C00SPC200 V600R006C00

  TE40 versions V500R002C00SPC600 V600R006C00

  TE50 versions V500R002C00SPC600 V600R006C00

  TE60 versions V100R001C01SPC100 V100R001C10 V500R002C00 V600R006C00

  TP3106 versions V100R002C00

  TP3206 versions V100R002C00 V100R002C10

  USG9500 versions V500R001C00 V500R001C30SPC100

  ViewPoint 9030 versions V100R011C02SPC100 V100R011C03SPC100");

  script_tag(name:"solution", value:"TE40 Resolved Product and Version: TEX0 V600R006C00SPC400

  Secospace USG6600 Resolved Product and Version: V500R001C60SPC200

  USG9500 Resolved Product and Version: V500R002C20SPC200

  DBS3900 TDD LTE Resolved Product and Version: V100R004C10SPC500

  ViewPoint 9030 Resolved Product and Version: V100R011C03SPC800

  NGFW Module Resolved Product and Version: V500R001C60SPC200

  S9700 Resolved Product and Version: V200R011C10

  TP3106 Resolved Product and Version: TP3206 V100R002C00SPC800

  Secospace USG6300 Resolved Product and Version: V500R001C60SPC200

  S7700 Resolved Product and Version: V200R011C10

  TE50 Resolved Product and Version: TEX0 V600R006C00SPC400

  NIP6300 Resolved Product and Version: V500R001C60SPC200

  RP200 Resolved Product and Version: TEX0 V600R006C00SPC400

  S12700 Resolved Product and Version: V200R011C10

  S1700 Resolved Product and Version: V200R011C10

  TE60 Resolved Product and Version: TEX0 V600R006C00SPC400

  S6700 Resolved Product and Version: V200R011C10

  TP3206 Resolved Product and Version: V100R002C00SPC800

  DP300 Resolved Product and Version: V500R002C00SPCb00

  S2700 Resolved Product and Version: V200R011C10

  S5700 Resolved Product and Version: V200R011C10

  NIP6600 Resolved Product and Version: V500R001C60SPC200

  IPS Module Resolved Product and Version: V500R001C60SPC200

  Secospace USG6500 Resolved Product and Version: V500R001C60SPC200

  TE30 Resolved Product and Version: TEX0 V600R006C00SPC400");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-pem-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:dbs3900_tdd_lte_firmware",
                     "cpe:/o:huawei:dp300_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:rp200_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware",
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
                     "cpe:/o:huawei:viewpoint_9030_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:dbs3900_tdd_lte_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R004C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R004C10SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R004C10SPC500");
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
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R002C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
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
else if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version =~ "^V200R006C10SPC100" || version =~ "^V200R009C00SPC200" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2700_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version =~ "^V200R006C00SPC100" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C60SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C60SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te30_firmware")  {
  if(version =~ "^V100R001C02SPC100" || version =~ "^V100R001C10" || version =~ "^V500R002C00SPC200" || version =~ "^V600R006C00") {
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
  if(version =~ "^V500R001C00" || version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C20SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C20SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:viewpoint_9030_firmware")  {
  if(version =~ "^V100R011C02SPC100" || version =~ "^V100R011C03SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V100R011C03SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R011C03SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

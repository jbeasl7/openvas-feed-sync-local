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
  script_oid("1.3.6.1.4.1.25623.1.0.143950");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-20 07:44:20 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 14:47:00 +0000 (Fri, 08 Dec 2017)");

  script_cve_id("CVE-2017-8147");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: MaxAge LSA Vulnerability in OSPF Protocol of Some Huawei Products (huawei-sa-20170720-01-ospf)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a MaxAge LSA vulnerability due to improper OSPF implementation.");

  script_tag(name:"insight", value:"Some Huawei products have a MaxAge LSA vulnerability due to improper OSPF implementation. When the device receives special LSA packets, the LS (Link Status) age would be set to MaxAge, 3600 seconds. An attacker can exploit this vulnerability to poison the route table and launch a DoS attack. (Vulnerability ID: HWPSIRT-2017-06059)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-8147.Huawei has released software updates to fix this vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to poison the route table and launch a DoS attack.");

  script_tag(name:"affected", value:"AC6005 versions V200R006C10SPC200

  AC6605 versions V200R006C10SPC200

  AR1200 versions V200R005C10CP0582T V200R005C10HP0581T V200R005C20SPC026T

  AR200 versions V200R005C20SPC026T

  AR3200 versions V200R005C20SPC026T

  CloudEngine 12800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00 V200R001C00

  CloudEngine 5800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00 V200R001C00

  CloudEngine 6800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00 V200R001C00

  CloudEngine 7800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00 V200R001C00

  CloudEngine 8800 versions V100R006C00 V200R001C00

  E600 versions V200R008C00

  NE20E-S versions V800R005C01SPC100 V800R005C01SPC200 V800R006C00SPC300 V800R007C00SPC200 V800R007C10SPC100 V800R008C10SPC300 V800R008C10SPC500

  S12700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00

  S1700 versions V100R006C00 V100R007C00 V200R006C00

  S2300 versions V100R005C00 V100R006C00 V100R006C03 V100R006C05 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R005C01 V200R005C02 V200R005C03 V200R006C00 V200R007C00 V200R008C00

  S2700 versions V100R005C00 V100R006C00 V100R006C03 V100R006C05 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R005C01 V200R005C02 V200R005C03 V200R006C00 V200R007C00 V200R008C00

  S5300 versions V100R005C00 V100R006C00 V100R006C01 V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R006C00 V200R007C00 V200R008C00

  S5700 versions V100R005C00 V100R006C00 V100R006C01 V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R006C00 V200R007C00 V200R008C00

  S6300 versions V100R006C00 V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R008C00

  S6700 versions V100R006C00 V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R003C02 V200R003C10 V200R005C00 V200R006C00 V200R007C00 V200R008C00

  S7700 versions V100R003C00 V100R006C00 V200R001C00 V200R001C01 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00

  S9300 versions V100R001C00 V100R002C00 V100R003C00 V100R006C00 V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R008C10

  S9700 versions V200R001C00 V200R002C00 V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00

  Secospace USG6600 versions V500R001C00 V500R001C00SPC050 V500R001C20 V500R001C30");

  script_tag(name:"solution", value:"S12700 Resolved Product and Version: V200R009C00

  Secospace USG6600 Resolved Product and Version: V500R001C60SPC300

  S6700 Resolved Product and Version: V200R009C00

  CloudEngine 8800 Resolved Product and Version: V200R002C50

  S5700 Resolved Product and Version: V200R009C00

  S1700 Resolved Product and Version: V200R009C00

  S2300 Resolved Product and Version: V200R009C00

  S6300 Resolved Product and Version: V200R009C00

  S9300 Resolved Product and Version: V200R009C00

  AC6005 Resolved Product and Version: V2R6C20

  S9700 Resolved Product and Version: V200R009C00

  Secospace USG6600 Resolved Product and Version: V500R001C30SPC600

  AR1200 Resolved Product and Version: v200r007c00spcb00

  CloudEngine 5800 Resolved Product and Version: V200R002C50

  AR3200 Resolved Product and Version: v200r007c00spcb00

  E600 Resolved Product and Version: V200R009C00

  S5300 Resolved Product and Version: V200R009C00

  CloudEngine 6800 Resolved Product and Version: V200R002C50

  NE20E-S Resolved Product and Version: V800R009C10SPC200

  CloudEngine 12800 Resolved Product and Version: V200R002C54

  CloudEngine 12800 Resolved Product and Version: V200R002C53

  S2700 Resolved Product and Version: V200R009C00

  CloudEngine 12800 Resolved Product and Version: V200R002C50

  CloudEngine 7800 Resolved Product and Version: V200R002C50

  AR200 Resolved Product and Version: v200r007c00spcb00

  CloudEngine 12800 Resolved Product and Version: V200R002C52

  S7700 Resolved Product and Version: V200R009C00

  CloudEngine 12800 Resolved Product and Version: V200R002C51

  AC6605 Resolved Product and Version: V2R6C20");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170720-01-ospf-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ac6005_firmware",
                     "cpe:/o:huawei:ac6605_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware",
                     "cpe:/o:huawei:e600_firmware",
                     "cpe:/o:huawei:ne20e-s_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2300_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5300_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6300_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9300_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ac6005_firmware")  {
  if(version =~ "^V200R006C10SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V2R6C20")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R6C20");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ac6605_firmware")  {
  if(version =~ "^V200R005C10CP0582T" || version =~ "^V200R005C10HP0581T" || version =~ "^V200R005C20SPC026T") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c00spcb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c00spcb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R005C20SPC026T") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c00spcb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c00spcb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R005C20SPC026T") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c00spcb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c00spcb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R005C20SPC026T") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c00spcb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c00spcb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C51")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C51");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware")  {
  if(version =~ "^V100R006C00" || version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:e600_firmware")  {
  if(version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ne20e-s_firmware")  {
  if(version =~ "^V800R005C01SPC100" || version =~ "^V800R005C01SPC200" || version =~ "^V800R006C00SPC300" || version =~ "^V800R007C00SPC200" || version =~ "^V800R007C10SPC100" || version =~ "^V800R008C10SPC300" || version =~ "^V800R008C10SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V800R009C10SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V800R009C10SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version =~ "^V100R006C00" || version =~ "^V100R007C00" || version =~ "^V200R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2300_firmware")  {
  if(version =~ "^V100R005C00" || version =~ "^V100R006C00" || version =~ "^V100R006C03" || version =~ "^V100R006C05" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R005C01" || version =~ "^V200R005C02" || version =~ "^V200R005C03" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2700_firmware")  {
  if(version =~ "^V100R005C00" || version =~ "^V100R006C00" || version =~ "^V100R006C03" || version =~ "^V100R006C05" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R005C01" || version =~ "^V200R005C02" || version =~ "^V200R005C03" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5300_firmware")  {
  if(version =~ "^V100R005C00" || version =~ "^V100R006C00" || version =~ "^V100R006C01" || version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version =~ "^V100R005C00" || version =~ "^V100R006C00" || version =~ "^V100R006C01" || version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6300_firmware")  {
  if(version =~ "^V100R006C00" || version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V100R006C00" || version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R003C02" || version =~ "^V200R003C10" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R006C00" || version =~ "^V200R001C00" || version =~ "^V200R001C01" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9300_firmware")  {
  if(version =~ "^V100R001C00" || version =~ "^V100R002C00" || version =~ "^V100R003C00" || version =~ "^V100R006C00" || version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R008C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R001C00" || version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C00SPC050" || version =~ "^V500R001C20" || version =~ "^V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C30SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

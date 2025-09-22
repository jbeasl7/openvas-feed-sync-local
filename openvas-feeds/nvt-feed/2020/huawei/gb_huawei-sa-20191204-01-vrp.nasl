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
  script_oid("1.3.6.1.4.1.25623.1.0.108800");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 18:01:00 +0000 (Wed, 18 Dec 2019)");

  script_cve_id("CVE-2019-19397");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Huawei VRP Platform (huawei-sa-20191204-01-vrp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is a weak algorithm vulnerability in some Huawei products. The affected products use weak algorithms by default. Attackers may exploit the vulnerability to cause information leaks. (Vulnerability ID: HWPSIRT-2019-02008)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-19397.Huawei has released software updates to fix this vulnerability.");

  script_tag(name:"impact", value:"Successful exploit may cause information leaks.");

  script_tag(name:"affected", value:"AR120-S versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500

  AR1200 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC200PWE V200R010C00SPC500 V200R010C00SPC500PWE V200R010C00SPC600 V300R003C00SPC500 V300R003C00SPC500PWE V300R003C00SPC600

  AR1200-S versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC600

  AR150 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R010C00SPC200 V200R010C00SPC600

  AR150-S versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500

  AR160 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC500 V200R010C00SPC600 V300R003C00SPC300 V300R003C00SPC300B808 V300R003C00SPC500 V300R003C00SPC500PWE V300R003C00SPC600

  AR200 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC600

  AR200-S versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500

  AR2200 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC200PWE V200R010C00SPC500 V200R010C00SPC500PWE V200R010C00SPC600 V300R003C00SPC300 V300R003C00SPC500 V300R003C00SPC500PWE V300R003C00SPC600

  AR2200-S versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC600

  AR3200 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V200R009C00SPC500PWE V200R010C00SPC200 V200R010C00SPC200PWE V200R010C00SPC500 V200R010C00SPC500PWE V200R010C00SPC600 V300R003C00SPC000 V300R003C00SPC500 V300R003C00SPC500PWE V300R003C00SPC600

  AR3600 versions V200R008C50SPC500 V200R008C50SPC500PWE V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500 V300R003C00SPC500 V300R003C00SPC600

  IPS Module versions V500R001C20SPC100 V500R001C30SPC100 V500R001C30SPC200

  NGFW Module versions V500R002C00SPC100 V500R002C00SPC200

  NIP6300 versions V500R001C30SPC100 V500R001C30SPC200

  NIP6600 versions V500R001C30SPC100 V500R001C30SPC200

  NetEngine16EX versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC300PWE V200R009C00SPC500

  S12700 versions V200R007C00SPC500 V200R007C01 V200R007C01B380 V200R007C01B400 V200R007C20 V200R008C00 V200R010C00SPC300 V200R011C10SPC500 V200R012C00SPC200

  S1700 versions V200R006C10SPC100 V200R010C00SPC300 V200R011C10SPC500 V200R012C00SPC200 V200R012C20

  S2700 versions V200R006C00SPC100 V200R006C10SPC100 V200R007C00SPC500 V200R008C00 V200R010C00SPC300 V200R011C00SPC200 V200R011C10SPC500 V200R012C00SPC200

  S5700 versions V200R005C00SPC500 V200R005C02 V200R005C03 V200R006C00SPC100 V200R007C00SPC500 V200R008C00 V200R010C00SPC300 V200R011C00SPC200 V200R011C10SPC500 V200R012C00SPC200 V200R012C20

  S6700 versions V200R005C00SPC500 V200R005C01 V200R005C02 V200R008C00 V200R010C00SPC300 V200R011C00SPC200 V200R011C10SPC500 V200R012C00SPC200

  S7700 versions V200R006C00SPC100 V200R007C00SPC500 V200R008C00 V200R010C00SPC300 V200R011C10SPC500 V200R012C00SPC200

  S9700 versions V200R006C00SPC100 V200R007C00SPC500 V200R007C01 V200R008C00 V200R010C00SPC300 V200R011C10SPC500 V200R012C00SPC200

  SRG1300 versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC500 V200R010C00SPC200 V200R010C00SPC600 V300R003C00SPC500

  SRG2300 versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC500 V200R010C00SPC200 V200R010C00SPC600 V300R003C00SPC500

  SRG3300 versions V200R008C50SPC500 V200R009C00SPC300 V200R009C00SPC500 V200R010C00SPC200 V200R010C00SPC600 V300R003C00SPC500

  Secospace AntiDDoS8000 versions V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600 V500R001C60SPC100 V500R001C60SPC101 V500R001C60SPC200 V500R001C60SPC300 V500R001C60SPC500 V500R001C60SPC600 V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6300 versions V500R001C30SPC100 V500R001C30SPC200

  Secospace USG6500 versions V500R001C30SPC100 V500R001C30SPC200

  USG6000V versions V500R005C00SPC100");

  script_tag(name:"solution", value:"S7700 Resolved Product and Version: V200R019C00

  AR150 Resolved Product and Version: AR3200 V200R010C10SPC600

  S6700 Resolved Product and Version: V200R019C00

  NetEngine16EX Resolved Product and Version: AR3200 V200R010C10SPC600

  AR3200 Resolved Product and Version: V200R010C10SPC600

  AR2200 Resolved Product and Version: AR3200 V200R010C10SPC600

  S2700 Resolved Product and Version: V200R019C00

  AR2200-S Resolved Product and Version: AR3200 V200R010C10SPC600

  SRG1300 Resolved Product and Version: AR3200 V200R010C10SPC600

  USG6000V Resolved Product and Version: V500R005C10SPC300

  AR120-S Resolved Product and Version: AR3200 V200R010C10SPC600

  NIP6600 Resolved Product and Version: V500R005C20SPC300

  Secospace USG6500 Resolved Product and Version: V500R005C20SPC300

  IPS Module Resolved Product and Version: V500R005C20SPC300

  S5700 Resolved Product and Version: V200R019C00

  S1700 Resolved Product and Version: V200R019C00

  AR200 Resolved Product and Version: AR3200 V200R010C10SPC600

  S9700 Resolved Product and Version: V200R019C00

  SRG2300 Resolved Product and Version: AR3200 V200R010C10SPC600

  AR3600 Resolved Product and Version: AR3200 V200R010C10SPC600

  AR1200-S Resolved Product and Version: AR3200 V200R010C10SPC600

  AR150-S Resolved Product and Version: AR3200 V200R010C10SPC600

  NGFW Module Resolved Product and Version: V500R005C20SPC300

  SRG3300 Resolved Product and Version: AR3200 V200R010C10SPC600

  Secospace USG6300 Resolved Product and Version: V500R005C20SPC300

  AR160 Resolved Product and Version: AR3200 V200R010C10SPC600

  NIP6300 Resolved Product and Version: V500R005C20SPC300

  S12700 Resolved Product and Version: V200R019C00

  AR1200 Resolved Product and Version: AR3200 V200R010C10SPC600

  Secospace AntiDDoS8000 Resolved Product and Version: V500R005C20SPC300

  AR200-S Resolved Product and Version: AR3200 V200R010C10SPC600");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-01-vrp-en");

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
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9700_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6000v_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC200PWE" || version =~ "^V200R010C00SPC500" || version =~ "^V200R010C00SPC500PWE" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC500" || version =~ "^V300R003C00SPC500PWE" || version =~ "^V300R003C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC500" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC300" || version =~ "^V300R003C00SPC300B808" || version =~ "^V300R003C00SPC500" || version =~ "^V300R003C00SPC500PWE" || version =~ "^V300R003C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC200PWE" || version =~ "^V200R010C00SPC500" || version =~ "^V200R010C00SPC500PWE" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC300" || version =~ "^V300R003C00SPC500" || version =~ "^V300R003C00SPC500PWE" || version =~ "^V300R003C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V200R009C00SPC500PWE" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC200PWE" || version =~ "^V200R010C00SPC500" || version =~ "^V200R010C00SPC500PWE" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC000" || version =~ "^V300R003C00SPC500" || version =~ "^V300R003C00SPC500PWE" || version =~ "^V300R003C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R008C50SPC500PWE" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500" || version =~ "^V300R003C00SPC500" || version =~ "^V300R003C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version =~ "^V500R001C20SPC100" || version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V500R002C00SPC100" || version =~ "^V500R002C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC300PWE" || version =~ "^V200R009C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version =~ "^V200R007C00SPC500" || version =~ "^V200R007C01" || version =~ "^V200R007C01B380" || version =~ "^V200R007C01B400" || version =~ "^V200R007C20" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version =~ "^V200R006C10SPC100" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200" || version =~ "^V200R012C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2700_firmware")  {
  if(version =~ "^V200R006C00SPC100" || version =~ "^V200R006C10SPC100" || version =~ "^V200R007C00SPC500" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C00SPC200" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version =~ "^V200R005C00SPC500" || version =~ "^V200R005C02" || version =~ "^V200R005C03" || version =~ "^V200R006C00SPC100" || version =~ "^V200R007C00SPC500" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C00SPC200" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200" || version =~ "^V200R012C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V200R005C00SPC500" || version =~ "^V200R005C01" || version =~ "^V200R005C02" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C00SPC200" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V200R006C00SPC100" || version =~ "^V200R007C00SPC500" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R006C00SPC100" || version =~ "^V200R007C00SPC500" || version =~ "^V200R007C01" || version =~ "^V200R008C00" || version =~ "^V200R010C00SPC300" || version =~ "^V200R011C10SPC500" || version =~ "^V200R012C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V200R019C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R019C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R008C50SPC500" || version =~ "^V200R009C00SPC300" || version =~ "^V200R009C00SPC500" || version =~ "^V200R010C00SPC200" || version =~ "^V200R010C00SPC600" || version =~ "^V300R003C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C10SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C10SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version =~ "^V500R001C20SPC200" || version =~ "^V500R001C20SPC300" || version =~ "^V500R001C20SPC500" || version =~ "^V500R001C20SPC600" || version =~ "^V500R001C60SPC100" || version =~ "^V500R001C60SPC101" || version =~ "^V500R001C60SPC200" || version =~ "^V500R001C60SPC300" || version =~ "^V500R001C60SPC500" || version =~ "^V500R001C60SPC600" || version =~ "^V500R005C00SPC100" || version =~ "^V500R005C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C20SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6000v_firmware")  {
  if(version =~ "^V500R005C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C10SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C10SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

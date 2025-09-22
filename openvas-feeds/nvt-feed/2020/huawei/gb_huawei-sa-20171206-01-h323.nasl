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
  script_oid("1.3.6.1.4.1.25623.1.0.143977");
  script_version("2021-08-03T11:00:50+0000");
  script_tag(name:"last_modification", value:"2021-08-03 11:00:50 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 05:47:43 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-22 17:05:00 +0000 (Thu, 22 Feb 2018)");

  script_cve_id("CVE-2017-17151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Input Validation Vulnerability in H323 Protocol of Huawei products (huawei-sa-20171206-01-h323)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an insufficient validation vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"There is an insufficient validation vulnerability in some Huawei products. Since packet validation is insufficient, an unauthenticated attacker may send special H323 packets to exploit the vulnerability. Successful exploit could allow the attacker to send malicious packets and result in DOS attacks. (Vulnerability ID: HWPSIRT-2017-03125)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17151.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could allow the attacker to send malicious packets and result in DOS attacks.");

  script_tag(name:"affected", value:"AR100 versions V200R008C20SPC700 V200R008C20SPC700PWE V200R008C20SPC800 V200R008C20SPC800PWE V200R008C30

AR100-S versions V200R007C00SPCa00 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C20SPC800PWE V200R008C30

AR110-S versions V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20SPC800 V200R008C30

AR120 versions V200R006C10 V200R006C10SPC300 V200R006C10SPC300PWE V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR120-S versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCa00 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR1200 versions V200R006C10 V200R006C10PWE V200R006C10SPC030 V200R006C10SPC300 V200R006C10SPC300PWE V200R006C10SPC600 V200R006C13 V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCa00 V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R007C02 V200R008C20 V200R008C20SPC600 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR1200-S versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C20SPC800PWE V200R008C30

AR150 versions V200R006C10 V200R006C10PWE V200R006C10SPC300 V200R006C10SPC300PWE V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R007C02 V200R007C02PWE V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR150-S versions V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR160 versions V200R006C10 V200R006C10PWE V200R006C10SPC100 V200R006C10SPC200 V200R006C10SPC300 V200R006C10SPC300PWE V200R006C10SPC600 V200R006C12 V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC500 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R007C02 V200R008C20 V200R008C20SPC500T V200R008C20SPC501T V200R008C20SPC600 V200R008C20SPC700 V200R008C20SPC800 V200R008C30 V200R008C30SPC100

AR200 versions V200R006C10 V200R006C10PWE V200R006C10SPC100 V200R006C10SPC300 V200R006C10SPC300PWE V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R008C20 V200R008C20SPC600 V200R008C20SPC700 V200R008C20SPC800 V200R008C20SPC900 V200R008C20SPC900PWE V200R008C30

AR200-S versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR2200 versions V200R006C10 V200R006C10PWE V200R006C10SPC300 V200R006C10SPC300PWE V200R006C10SPC600 V200R006C13 V200R006C16PWE V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC500 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCa00 V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R007C02 V200R008C20 V200R008C20SPC600 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

AR2200-S versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C20SPC800PWE V200R008C30

AR3200 versions V200R006C10 V200R006C10PWE V200R006C10SPC100 V200R006C10SPC200 V200R006C10SPC300 V200R006C10SPC300PWE V200R006C10SPC600 V200R006C11 V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC500 V200R007C00SPC510T V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCa00 V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C00SPCc00 V200R007C01 V200R007C02 V200R008C00 V200R008C10 V200R008C20 V200R008C20B560 V200R008C20B570 V200R008C20B580 V200R008C20SPC700 V200R008C20SPC800 V200R008C30 V200R008C30B010 V200R008C30B020 V200R008C30B030 V200R008C30B050 V200R008C30B060 V200R008C30B070 V200R008C30B080 V200R008C30SPC067T

AR3600 versions V200R006C10 V200R006C10PWE V200R006C10SPC100 V200R006C10SPC300 V200R006C10SPC300PWE V200R007C00 V200R007C00PWE V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC600PWE V200R007C00SPC900 V200R007C00SPC900PWE V200R007C00SPCb00 V200R007C00SPCb00PWE V200R007C01 V200R008C20

AR510 versions V200R006C10 V200R006C10PWE V200R006C10SPC200 V200R006C12 V200R006C13 V200R006C15 V200R006C16 V200R006C17 V200R007C00SPC180T V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C30

DP300 versions V500R002C00 V500R002C00SPC100 V500R002C00SPC200 V500R002C00SPC300 V500R002C00SPC400 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC800 V500R002C00SPC900

NetEngine16EX versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C20SPC700 V200R008C20SPC800 V200R008C30

RP200 versions V500R002C00SPC200

SRG1300 versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R007C02 V200R008C20 V200R008C30

SRG2300 versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R007C02 V200R008C20 V200R008C30

SRG3300 versions V200R006C10 V200R006C10SPC300 V200R007C00 V200R007C00SPC100 V200R007C00SPC200 V200R007C00SPC600 V200R007C00SPC900 V200R007C00SPCb00 V200R008C20 V200R008C30

TE30 versions V100R001C02SPC100 V100R001C02SPC200 V100R001C10 V100R001C10SPC100 V100R001C10SPC300 V100R001C10SPC600 V100R001C10SPC800 V500R002C00SPC200 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC900 V500R002C00SPCb00

TE40 versions V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC900 V500R002C00SPCb00 V600R006C00

TE50 versions V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPCb00

TE60 versions V100R001C01SPC100 V100R001C10 V100R001C10B010 V100R001C10SPC300 V100R001C10SPC400 V100R001C10SPC502T V100R001C10SPC600 V100R001C10SPC700 V100R001C10SPC800 V100R001C10SPC900 V500R002C00 V500R002C00SPC100 V500R002C00SPC200 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPCa00 V500R002C00SPCb00 V600R006C00

TP3106 versions V100R001C06B020 V100R002C00 V100R002C00B026 V100R002C00B027 V100R002C00B028 V100R002C00B029 V100R002C00SPC100B022 V100R002C00SPC100B022SP01 V100R002C00SPC100B023 V100R002C00SPC100B024 V100R002C00SPC100B025 V100R002C00SPC101T V100R002C00SPC200 V100R002C00SPC400 V100R002C00SPC600 V100R002C00T

TP3206 versions V100R002C00 V100R002C00SPC200 V100R002C00SPC400 V100R002C00SPC600

ViewPoint 8660 versions V100R008C03B013SP02 V100R008C03B013SP03 V100R008C03B013SP04 V100R008C03SPC100 V100R008C03SPC100B010 V100R008C03SPC100B011 V100R008C03SPC200 V100R008C03SPC200T V100R008C03SPC300 V100R008C03SPC400 V100R008C03SPC500 V100R008C03SPC600 V100R008C03SPC600T V100R008C03SPC700 V100R008C03SPC800 V100R008C03SPC900 V100R008C03SPCa00 V100R008C03SPCb00 V100R008C03SPCc00

ViewPoint 9030 versions V100R011C02SPC100 V100R011C02SPC100B010 V100R011C03B012SP15 V100R011C03B012SP16 V100R011C03B015SP03 V100R011C03LGWL01SPC100 V100R011C03LGWL01SPC100B012 V100R011C03SPC100 V100R011C03SPC100B010 V100R011C03SPC100B011 V100R011C03SPC100B012 V100R011C03SPC200 V100R011C03SPC300 V100R011C03SPC400 V100R011C03SPC500");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-h323-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar100_firmware",
                     "cpe:/o:huawei:ar100-s_firmware",
                     "cpe:/o:huawei:ar110-s_firmware",
                     "cpe:/o:huawei:ar120_firmware",
                     "cpe:/o:huawei:ar120-s_firmware",
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
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:rp200_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:te30_firmware",
                     "cpe:/o:huawei:te40_firmware",
                     "cpe:/o:huawei:te50_firmware",
                     "cpe:/o:huawei:te60_firmware",
                     "cpe:/o:huawei:tp3106_firmware",
                     "cpe:/o:huawei:tp3206_firmware",
                     "cpe:/o:huawei:viewpoint_8660_firmware",
                     "cpe:/o:huawei:viewpoint_9030_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar100_firmware")  {
  if(version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC700PWE" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C20SPC800PWE" || version =~ "^V200R008C30") {    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar100-s_firmware")  {
  if(version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C20SPC800PWE" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar110-s_firmware")  {
  if(version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar120_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC030" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R006C10SPC600" || version =~ "^V200R006C13" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC600" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C20SPC800PWE" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R007C02PWE" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC100" || version =~ "^V200R006C10SPC200" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R006C10SPC600" || version =~ "^V200R006C12" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC500" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC500T" || version =~ "^V200R008C20SPC501T" || version =~ "^V200R008C20SPC600" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30" || version =~ "^V200R008C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC100" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC600" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C20SPC900" || version =~ "^V200R008C20SPC900PWE" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R006C10SPC600" || version =~ "^V200R006C13" || version =~ "^V200R006C16PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC500" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC600" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C20SPC800PWE" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC100" || version =~ "^V200R006C10SPC200" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R006C10SPC600" || version =~ "^V200R006C11" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC500" || version =~ "^V200R007C00SPC510T" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C00SPCC00" || version =~ "^V200R007C01" || version =~ "^V200R007C02" || version =~ "^V200R008C00" || version =~ "^V200R008C10" || version =~ "^V200R008C20" || version =~ "^V200R008C20B560" || version =~ "^V200R008C20B570" || version =~ "^V200R008C20B580" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30" || version =~ "^V200R008C30B010" || version =~ "^V200R008C30B020" || version =~ "^V200R008C30B030" || version =~ "^V200R008C30B050" || version =~ "^V200R008C30B060" || version =~ "^V200R008C30B070" || version =~ "^V200R008C30B080" || version =~ "^V200R008C30SPC067T") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC100" || version =~ "^V200R006C10SPC300" || version =~ "^V200R006C10SPC300PWE" || version =~ "^V200R007C00" || version =~ "^V200R007C00PWE" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC600PWE" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPC900PWE" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCB00PWE" || version =~ "^V200R007C01" || version =~ "^V200R008C20") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar510_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10PWE" || version =~ "^V200R006C10SPC200" || version =~ "^V200R006C12" || version =~ "^V200R006C13" || version =~ "^V200R006C15" || version =~ "^V200R006C16" || version =~ "^V200R006C17" || version =~ "^V200R007C00SPC180T" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:dp300_firmware")  {
  if(version =~ "^V500R002C00" || version =~ "^V500R002C00SPC100" || version =~ "^V500R002C00SPC200" || version =~ "^V500R002C00SPC300" || version =~ "^V500R002C00SPC400" || version =~ "^V500R002C00SPC500" || version =~ "^V500R002C00SPC600" || version =~ "^V500R002C00SPC800" || version =~ "^V500R002C00SPC900") {
    if (!patch || version_is_less(version: patch, test_version: "V500R002C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R002C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C20SPC700" || version =~ "^V200R008C20SPC800" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:rp200_firmware")  {
  if(version =~ "^V500R002C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C02" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R006C10" || version =~ "^V200R006C10SPC300" || version =~ "^V200R007C00" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC200" || version =~ "^V200R007C00SPC600" || version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R008C20" || version =~ "^V200R008C30") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te30_firmware")  {
  if(version =~ "^V100R001C02SPC100" || version =~ "^V100R001C02SPC200" || version =~ "^V100R001C10" || version =~ "^V100R001C10SPC100" || version =~ "^V100R001C10SPC300" || version =~ "^V100R001C10SPC600" || version =~ "^V100R001C10SPC800" || version =~ "^V500R002C00SPC200" || version =~ "^V500R002C00SPC600" || version =~ "^V500R002C00SPC700" || version =~ "^V500R002C00SPC900" || version =~ "^V500R002C00SPCB00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te40_firmware")  {
  if(version =~ "^V500R002C00SPC600" || version =~ "^V500R002C00SPC700" || version =~ "^V500R002C00SPC900" || version =~ "^V500R002C00SPCB00" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te50_firmware")  {
  if(version =~ "^V500R002C00SPC600" || version =~ "^V500R002C00SPC700" || version =~ "^V500R002C00SPCB00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:te60_firmware")  {
  if(version =~ "^V100R001C01SPC100" || version =~ "^V100R001C10" || version =~ "^V100R001C10B010" || version =~ "^V100R001C10SPC300" || version =~ "^V100R001C10SPC400" || version =~ "^V100R001C10SPC502T" || version =~ "^V100R001C10SPC600" || version =~ "^V100R001C10SPC700" || version =~ "^V100R001C10SPC800" || version =~ "^V100R001C10SPC900" || version =~ "^V500R002C00" || version =~ "^V500R002C00SPC100" || version =~ "^V500R002C00SPC200" || version =~ "^V500R002C00SPC600" || version =~ "^V500R002C00SPC700" || version =~ "^V500R002C00SPC800" || version =~ "^V500R002C00SPC900" || version =~ "^V500R002C00SPCA00" || version =~ "^V500R002C00SPCB00" || version =~ "^V600R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V600R006C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V600R006C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:tp3106_firmware")  {
  if(version =~ "^V100R001C06B020" || version =~ "^V100R002C00" || version =~ "^V100R002C00B026" || version =~ "^V100R002C00B027" || version =~ "^V100R002C00B028" || version =~ "^V100R002C00B029" || version =~ "^V100R002C00SPC100B022" || version =~ "^V100R002C00SPC100B022SP01" || version =~ "^V100R002C00SPC100B023" || version =~ "^V100R002C00SPC100B024" || version =~ "^V100R002C00SPC100B025" || version =~ "^V100R002C00SPC101T" || version =~ "^V100R002C00SPC200" || version =~ "^V100R002C00SPC400" || version =~ "^V100R002C00SPC600" || version =~ "^V100R002C00T") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:tp3206_firmware")  {
  if(version =~ "^V100R002C00" || version =~ "^V100R002C00SPC200" || version =~ "^V100R002C00SPC400" || version =~ "^V100R002C00SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:viewpoint_8660_firmware")  {
  if(version =~ "^V100R008C03B013SP02" || version =~ "^V100R008C03B013SP03" || version =~ "^V100R008C03B013SP04" || version =~ "^V100R008C03SPC100" || version =~ "^V100R008C03SPC100B010" || version =~ "^V100R008C03SPC100B011" || version =~ "^V100R008C03SPC200" || version =~ "^V100R008C03SPC200T" || version =~ "^V100R008C03SPC300" || version =~ "^V100R008C03SPC400" || version =~ "^V100R008C03SPC500" || version =~ "^V100R008C03SPC600" || version =~ "^V100R008C03SPC600T" || version =~ "^V100R008C03SPC700" || version =~ "^V100R008C03SPC800" || version =~ "^V100R008C03SPC900" || version =~ "^V100R008C03SPCA00" || version =~ "^V100R008C03SPCB00" || version =~ "^V100R008C03SPCC00") {
    if (!patch || version_is_less(version: patch, test_version: "V100R008C03SPCe00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R008C03SPCe00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:viewpoint_9030_firmware")  {
  if(version =~ "^V100R011C02SPC100" || version =~ "^V100R011C02SPC100B010" || version =~ "^V100R011C03B012SP15" || version =~ "^V100R011C03B012SP16" || version =~ "^V100R011C03B015SP03" || version =~ "^V100R011C03LGWL01SPC100" || version =~ "^V100R011C03LGWL01SPC100B012" || version =~ "^V100R011C03SPC100" || version =~ "^V100R011C03SPC100B010" || version =~ "^V100R011C03SPC100B011" || version =~ "^V100R011C03SPC100B012" || version =~ "^V100R011C03SPC200" || version =~ "^V100R011C03SPC300" || version =~ "^V100R011C03SPC400" || version =~ "^V100R011C03SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C00SPC800")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C00SPC800");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

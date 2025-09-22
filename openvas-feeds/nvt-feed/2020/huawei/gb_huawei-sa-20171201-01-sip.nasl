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
  script_oid("1.3.6.1.4.1.25623.1.0.143974");
  script_version("2021-08-17T12:00:57+0000");
  script_tag(name:"last_modification", value:"2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 03:44:14 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-27 15:25:00 +0000 (Tue, 27 Feb 2018)");

  script_cve_id("CVE-2017-15334", "CVE-2017-15335", "CVE-2017-15336", "CVE-2017-15337", "CVE-2017-15338", "CVE-2017-15339");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple Buffer Overflow Vulnerabilities in Some Huawei Products (huawei-sa-20171201-01-sip)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There are three buffer overflow vulnerabilities in the SIP backup feature of some Huawei products.");

  script_tag(name:"insight", value:"There are three buffer overflow vulnerabilities in the SIP backup feature of some Huawei products. An attacker may send specially crafted messages to the affected products. Due to the insufficient validation of some values for SIP messages, successful exploit may cause services abnormal. (Vulnerability ID: HWPSIRT-2017-04052, HWPSIRT-2017-04053 and HWPSIRT-2017-04054)The three vulnerabilities have been assigned three Common Vulnerabilities and Exposures (CVE) IDs: CVE-2017-15334, CVE-2017-15335 and CVE-2017-15336.There are three buffer overflow vulnerabilities in the SIP module of some Huawei products. An attacker would have to find a way to craft specific messages to the affected products. Due to the insufficient validation for SIP messages, successful exploit may cause services abnormal. (Vulnerability ID: HWPSIRT-2017-04055, HWPSIRT-2017-04056 and HWPSIRT-2017-04057)The three vulnerabilities have been assigned three Common Vulnerabilities and Exposures (CVE) IDs: CVE-2017-15337, CVE-2017-15338 and CVE-2017-15339.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause services abnormal.");

  script_tag(name:"affected", value:"DP300 versions V500R002C00

IPS Module versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

NGFW Module versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30 V500R001C00 V500R001C20SPC100 V500R002C00 V500R002C10

NIP6300 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

NIP6600 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50

NIP6800 versions V500R001C50

RP200 versions V500R002C00SPC200 V600R006C00

SVN5600 versions V200R003C00SPC100 V200R003C10

SVN5800 versions V200R003C00SPC100 V200R003C10

SVN5800-C versions V200R003C00SPC100 V200R003C10

SeMG9811 versions V300R001C01SPC500

Secospace USG6300 versions V100R001C10SPC200 V100R001C20SPC002T V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

Secospace USG6500 versions V100R001C10SPC200 V100R001C20SPC100 V100R001C30B018 V500R001C00 V500R001C20 V500R001C30 V500R001C50

Secospace USG6600 versions V100R001C00SPC200 V100R001C20SPC070B710 V100R001C30 V500R001C00 V500R001C20 V500R001C30 V500R001C50

TE30 versions V100R001C02B053SP02 V100R001C10 V500R002C00SPC200 V600R006C00

TE40 versions V500R002C00SPC600 V600R006C00

TE50 versions V500R002C00SPC600 V600R006C00

TE60 versions V100R001C01SPC100 V100R001C10 V500R002C00 V600R006C00

USG9500 versions V500R001C00 V500R001C20 V500R001C30

USG9520 versions V300R001C01SPC500 V300R001C20SPC200

USG9560 versions V300R001C01SPC500 V300R001C20SPC200

USG9580 versions V300R001C01SPC500 V300R001C20SPC200

VP9660 versions V200R001C02SPC100 V200R001C30SPC100 V500R002C00 V500R002C00SPC200 V500R002C00SPC300 V500R002C00SPC400 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPCa00 V500R002C00SPCb00 V500R002C00SPCc00 V500R002C10

ViewPoint 8660 versions V100R008C03B013SP02 V100R008C03B013SP03 V100R008C03B013SP04 V100R008C03SPC100 V100R008C03SPC100B010 V100R008C03SPC100B011 V100R008C03SPC200 V100R008C03SPC300 V100R008C03SPC400 V100R008C03SPC500 V100R008C03SPC600 V100R008C03SPC700 V100R008C03SPC800 V100R008C03SPC900 V100R008C03SPCa00 V100R008C03SPCb00

ViewPoint 9030 versions V100R011C02B013SP40 V100R011C03B012SP15

eSpace U1981 versions V100R001C20SPC700 V200R003C00SPC700 V200R003C20SPC800 V200R003C20SPC900 V200R003C30SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171201-01-sip-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:usg6[35]00_firmware") {
  if (version =~ "^V100R001C10" || version =~ "^V100R001C20" || version =~ "^V100R001C30" ||
      version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" ||
      version =~ "^V500R001C50") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R001C60SPC500", fixed_patch: "V500R001SPH015");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version =~ "^V100R001C00" || version =~ "^V100R001C20" || version =~ "^V100R001C30" ||
      version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" ||
      version =~ "^V500R001C50") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R001C60SPC500", fixed_patch: "V500R001SPH015");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware") {
  if (version =~ "^V300R001C01" || version =~ "^V500R001C00" || version =~ "^V500R001C20" ||
      version =~ "^V500R001C30") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R001C60SPC500", fixed_patch: "V500R001SPH015");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

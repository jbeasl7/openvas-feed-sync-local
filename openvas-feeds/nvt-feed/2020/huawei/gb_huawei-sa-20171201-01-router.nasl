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
  script_oid("1.3.6.1.4.1.25623.1.0.143973");
  script_version("2021-08-06T11:00:51+0000");
  script_tag(name:"last_modification", value:"2021-08-06 11:00:51 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-05-26 03:30:27 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-15349");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability in Some Huawei Products (huawei-sa-20171201-01-router)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a memory leak vulnerability.");

  script_tag(name:"insight", value:"Some Huawei products have a memory leak vulnerability. An unauthenticated attacker may send specific Resource ReServation Protocol (RSVP) Path Error or Path Tear packets to the affected products. Due to not release the memory to handle the packets, successful exploit will result in memory leak of the affected products and lead to a DoS condition. (Vulnerability ID: HWPSIRT-2017-02032)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15349.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit will result in memory leak of the affected products.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00

CloudEngine 5800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00

CloudEngine 6800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00

CloudEngine 7800 versions V100R003C00 V100R005C00 V100R005C10 V100R006C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171201-01-router-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware")  {
  if(version =~ "^V100R003C00" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R002C50")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R002C50");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

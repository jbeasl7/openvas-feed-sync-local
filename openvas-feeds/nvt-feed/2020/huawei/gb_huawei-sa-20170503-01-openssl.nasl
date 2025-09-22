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
  script_oid("1.3.6.1.4.1.25623.1.0.143949");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-05-20 07:21:29 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:16:00 +0000 (Tue, 16 Aug 2022)");

  script_cve_id("CVE-2017-3730", "CVE-2017-3731", "CVE-2017-3732");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Multiple OpenSSL Vulnerabilities in January 2017 (huawei-sa-20170503-01-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"On January 26, 2017, the OpenSSL Software Foundation released a security advisory that included three new vulnerabilities.");

  script_tag(name:"insight", value:"On January 26, 2017, the OpenSSL Software Foundation released a security advisory that included three new vulnerabilities.If a malicious server supplies bad parameters for a DHE or ECDHE key exchange then this can result in the client attempting to dereference a NULL pointer leading to a client crash. This could be exploited in a Denial of Service attack. (Vulnerability ID: HWPSIRT-2017-02005)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-3730.If an SSL/TLS server or client is running on a 32-bit host, and a specific cipher is being used, a truncated packet can cause that server or client to perform an out-of-bounds read, usually resulting in a crash. (Vulnerability ID: HWPSIRT-2017-02006)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-3731.There is a vulnerability in the x86_64 Montgomery squaring procedure, if DH parameters are used and a private key is shared between multiple clients, a successful exploit could allow the attacker to access sensitive private key information. (Vulnerability ID: HWPSIRT-2017-02007)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-3732.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"A successful exploit may cause OpenSSL to crash when connecting to a malicious server.");

  script_tag(name:"affected", value:"AC6005 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC300PWE V200R007C10SPH201 V200R007C10SPH301 V200R007C10SPH301PWE

  AC6605 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC300PWE V200R007C10SPH201 V200R007C10SPH301 V200R007C10SPH301PWE

  AP2000 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC500 V200R007C10SPC600

  AP3000 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC500 V200R007C10SPC600

  AP4000 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC500 V200R007C10SPC600

  AP6000 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC500 V200R007C10SPC600

  AP7000 versions V200R007C10SPC200 V200R007C10SPC300 V200R007C10SPC500 V200R007C10SPC600

  IPS Module versions V500R001C30 V500R001C50 V500R001C50PWE

  NGFW Module versions V500R002C00 V500R002C10 V500R002C10PWE

  OceanStor 9000 versions V300R005C00

  OceanStor Backup Software versions V200R001C00

  RH5885 V3 versions V100R003C01 V100R003C10

  Secospace AntiDDoS8000 versions V500R001C60SPC501 V500R001C60SPC600 V500R001C60SPH601 V500R005C00SPC100

  Secospace AntiDDoS8030 versions V500R001C60SPC100 V500R001C60SPC300 V500R001C60SPC500 V500R001C80

  Secospace USG6600 versions V500R001C30 V500R001C50 V500R001C50PWE

  UPS2000 versions V100R002C02 V200R001C31 V200R001C90

  USG9500 versions V500R001C30SPC100 V500R001C30SPC200

  eSpace VCN3000 versions V100R002C10SPC103 V100R002C20SPC207.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170503-01-openssl-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ac6005_firmware",
                     "cpe:/o:huawei:ac6605_firmware",
                     "cpe:/o:huawei:ap2000_firmware",
                     "cpe:/o:huawei:ap3000_firmware",
                     "cpe:/o:huawei:ap4000_firmware",
                     "cpe:/o:huawei:ap6000_firmware",
                     "cpe:/o:huawei:ap7000_firmware",
                     "cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:oceanstor_9000_firmware",
                     "cpe:/o:huawei:oceanstor_backup_firmware",
                     "cpe:/o:huawei:rh5885_v3_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:antiddos8030_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:ups2000_firmware",
                     "cpe:/o:huawei:usg9500_firmware",
                     "cpe:/o:huawei:espace_vcn3000_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ac6005_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC300PWE" || version =~ "^V200R007C10SPH201" || version =~ "^V200R007C10SPH301" || version =~ "^V200R007C10SPH301PWE") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c20spc200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c20spc200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ac6605_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC300PWE" || version =~ "^V200R007C10SPH201" || version =~ "^V200R007C10SPH301" || version =~ "^V200R007C10SPH301PWE") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c20spc200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c20spc200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap2000_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC500" || version =~ "^V200R007C10SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C20SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C20SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap3000_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC500" || version =~ "^V200R007C10SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C20SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C20SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap4000_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC500" || version =~ "^V200R007C10SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C20SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C20SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap6000_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC500" || version =~ "^V200R007C10SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c20spc200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c20spc200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ap7000_firmware")  {
  if(version =~ "^V200R007C10SPC200" || version =~ "^V200R007C10SPC300" || version =~ "^V200R007C10SPC500" || version =~ "^V200R007C10SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "v200r007c20spc200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "v200r007c20spc200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version =~ "^V500R001C30" || version =~ "^V500R001C50" || version =~ "^V500R001C50PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V5R5C00SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V5R5C00SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V500R002C00" || version =~ "^V500R002C10" || version =~ "^V500R002C10PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V5R5C00SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V5R5C00SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:oceanstor_9000_firmware")  {
  if(version =~ "^V300R005C00") {
    if (!patch || version_is_less(version: patch, test_version: "V300R006C00SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V300R006C00SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:oceanstor_backup_firmware")  {
  if(version =~ "^V200R001C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R001C00SPC203")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R001C00SPC203");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:rh5885_v3_firmware")  {
  if(version =~ "^V100R003C01" || version =~ "^V100R003C10") {
    if (!patch || version_is_less(version: patch, test_version: "V100R003C10SPC111")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R003C10SPC111");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version =~ "^V500R001C60SPC501" || version =~ "^V500R001C60SPC600" || version =~ "^V500R001C60SPH601" || version =~ "^V500R005C00SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8030_firmware")  {
  if(version =~ "^V500R001C60SPC100" || version =~ "^V500R001C60SPC300" || version =~ "^V500R001C60SPC500" || version =~ "^V500R001C80") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C30" || version =~ "^V500R001C50" || version =~ "^V500R001C50PWE") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C30SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ups2000_firmware")  {
  if(version =~ "^V100R002C02" || version =~ "^V200R001C31" || version =~ "^V200R001C90") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C02SPC302")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C02SPC302");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg9500_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R001C30SPC600")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R001C30SPC600");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:espace_vcn3000_firmware")  {
  if(version =~ "^V100R002C10SPC103" || version =~ "^V100R002C20SPC207") {
    if (!patch || version_is_less(version: patch, test_version: "V100R002C30")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V100R002C30");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

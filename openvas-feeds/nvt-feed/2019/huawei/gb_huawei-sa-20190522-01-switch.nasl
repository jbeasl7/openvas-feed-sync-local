# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:huawei:s";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142505");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2019-06-26 03:10:43 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 11:15:00 +0000 (Fri, 26 Jul 2019)");

  script_cve_id("CVE-2019-5285");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Huawei S Series Switch Products (huawei-sa-20190522-01-switch)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei S series switches have a DoS vulnerability.");

  script_tag(name:"insight", value:"Some Huawei S series switches have a DoS vulnerability. An unauthenticated remote attacker can send crafted packets to the affected device to exploit this vulnerability. Due to insufficient verification of the packets, successful exploitation may cause the device reboot and denial of service (DoS) condition. (Vulnerability ID: HWPSIRT-2019-03191)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5285.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploitation may cause the device reboot and denial of service (DoS) condition.");

  script_tag(name:"affected", value:"S12700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S1700 versions V200R008C00 V200R009C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S2300 versions V200R003C00 V200R005C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S2700 versions V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S5300 versions V200R003C00 V200R005C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S5700 versions V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S600-E versions V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S6300 versions V200R003C00 V200R005C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S6700 versions V200R003C00 V200R005C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S7700 versions V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S7900 versions V200R011C10 V200R012C00 V200R013C00

S9300 versions V200R003C00 V200R008C00 V200R008C10 V200R010C00 V200R011C10 V200R012C00 V200R013C00

S9300X versions V200R010C00 V200R011C10 V200R012C00 V200R013C00

S9700 versions V200R003C00 V200R005C00 V200R006C00 V200R007C00 V200R008C00 V200R010C00 V200R011C10 V200R012C00 V200R013C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190522-01-switch-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s1700_firmware",
                     "cpe:/o:huawei:s2300_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s5300_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s600-e_firmware",
                     "cpe:/o:huawei:s6300_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s7900_firmware",
                     "cpe:/o:huawei:s9300_firmware",
                     "cpe:/o:huawei:s9300x_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:s12700_firmware")  {
  if(version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s1700_firmware")  {
  if(version =~ "^V200R008C00" || version =~ "^V200R009C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R012SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R012SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2300_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH025")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R005SPH025");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s2700_firmware")  {
  if(version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5300_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R012SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R012SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010SPH017")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010SPH017");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s600-e_firmware")  {
  if(version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R013C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6300_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R012SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R012SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R011SPH009")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R011SPH009");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7700_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R012SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R012SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s7900_firmware")  {
  if(version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R013C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R013C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9300_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R008C00" || version =~ "^V200R008C10" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R008SPH021")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R008SPH021");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9300x_firmware")  {
  if(version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R012SPH003")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R012SPH003");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s9700_firmware")  {
  if(version =~ "^V200R003C00" || version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R010C00" || version =~ "^V200R011C10" || version =~ "^V200R012C00" || version =~ "^V200R013C00") {
    if (!patch || version_is_less(version: patch, test_version: "V200R010C00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R010C00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

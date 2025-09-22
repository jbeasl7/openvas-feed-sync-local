# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143269");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2019-12-18 06:50:55 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 15:11:00 +0000 (Wed, 18 Dec 2019)");

  script_cve_id("CVE-2019-5290");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in Some Huawei Products (huawei-sa-20191204-02-dos)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a DoS security vulnerability.");

  script_tag(name:"insight", value:"Some Huawei products have a DoS security vulnerability. Attackers with certain permissions perform specific operations on affected devices. Because the pointer in the program is not processed properly, the vulnerability can be exploited to cause the device to be abnormal. (Vulnerability ID: HWPSIRT-2019-04202)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5290.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker may exploit the vulnerability to cause the device abnormal.");

  script_tag(name:"affected", value:"IPS Module versions V500R001C30SPC100

  NGFW Module versions V500R002C00SPC200

  NIP6300 versions V500R001C30SPC200

  NIP6600 versions V500R001C30SPC100 V500R001C30SPC200

  S5700 versions V200R005C00SPC500 V200R005C02 V200R005C03 V200R006C00SPC100 V200R006C00SPC300 V200R006C00SPC500 V200R007C00SPC100 V200R007C00SPC500 V200R008C00

  S6700 versions V200R005C00SPC500 V200R005C01 V200R005C02 V200R008C00

  Secospace AntiDDoS8000 versions V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600

  Secospace USG6300 versions V500R001C30SPC100 V500R001C30SPC200

  Secospace USG6500 versions V500R001C30SPC100 V500R001C30SPC200

  Secospace USG6600 versions V500R001C30SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-02-dos-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ips_module_firmware",
                     "cpe:/o:huawei:ngfw_module_firmware",
                     "cpe:/o:huawei:nip6300_firmware",
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ips_module_firmware")  {
  if(version =~ "^V500R001C30SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ngfw_module_firmware")  {
  if(version =~ "^V500R002C00SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6300_firmware")  {
  if(version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s5700_firmware")  {
  if(version =~ "^V200R005C00SPC500" || version =~ "^V200R005C02" || version =~ "^V200R005C03" || version =~ "^V200R006C00SPC100" || version =~ "^V200R006C00SPC300" || version =~ "^V200R006C00SPC500" || version =~ "^V200R007C00SPC100" || version =~ "^V200R007C00SPC500" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R11C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R11C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:s6700_firmware")  {
  if(version =~ "^V200R005C00SPC500" || version =~ "^V200R005C01" || version =~ "^V200R005C02" || version =~ "^V200R008C00") {
    if (!patch || version_is_less(version: patch, test_version: "V2R11C10")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V2R11C10");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version =~ "^V500R001C20SPC200" || version =~ "^V500R001C20SPC300" || version =~ "^V500R001C20SPC500" || version =~ "^V500R001C20SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC300")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC300");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6500_firmware")  {
  if(version =~ "^V500R001C30SPC100" || version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C30SPC200") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

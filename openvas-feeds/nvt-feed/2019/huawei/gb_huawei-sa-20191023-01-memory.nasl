# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143121");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2019-11-14 04:35:54 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-18 14:23:00 +0000 (Mon, 18 Nov 2019)");

  script_cve_id("CVE-2019-5293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability in Some Huawei Products (huawei-sa-20191023-01-memory)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a memory leak vulnerability when handling some messages.");

  script_tag(name:"insight", value:"Some Huawei products have a memory leak vulnerability when handling some messages. A remote attacker with operation privilege could exploit the vulnerability by sending specific messages continuously. Successful exploit may cause some service abnormal. (Vulnerability ID: HWPSIRT-2019-04075)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5293.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may cause some service abnormal.");

  script_tag(name:"affected", value:"AR120-S versions V200R005C20 V200R006C10

  AR1200 versions V200R005C20 V200R006C10

  AR1200-S versions V200R005C20 V200R006C10

  AR150 versions V200R005C20 V200R006C10

  AR150-S versions V200R005C20 V200R006C10

  AR160 versions V200R005C20 V200R006C10

  AR200 versions V200R005C20 V200R006C10

  AR200-S versions V200R005C20 V200R006C10

  AR2200 versions V200R005C20 V200R006C10

  AR2200-S versions V200R005C20 V200R006C10

  AR3200 versions V200R005C20 V200R006C10

  AR3600 versions V200R006C10

  NIP6600 versions V500R001C30

  NetEngine16EX versions V200R005C20 V200R006C10

  SRG1300 versions V200R005C20 V200R006C10

  SRG2300 versions V200R005C20 V200R006C10

  SRG3300 versions V200R005C20 V200R006C10

  Secospace AntiDDoS8000 versions V500R001C00 V500R001C20SPC200 V500R001C20SPC300 V500R001C20SPC500 V500R001C20SPC600

  Secospace USG6300 versions V500R001C30

  Secospace USG6600 versions V500R001C30

  USG6000V versions V500R001C10 V500R001C10SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191023-01-memory-en");

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
                     "cpe:/o:huawei:nip6600_firmware",
                     "cpe:/o:huawei:netengine16ex_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware",
                     "cpe:/o:huawei:antiddos8000_firmware",
                     "cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg6000v_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar120-s_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar1200-s_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar150-s_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar160_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar200-s_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar2200-s_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:ar3600_firmware")  {
  if(version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:nip6600_firmware")  {
  if(version =~ "^V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:netengine16ex_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg1300_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg2300_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:srg3300_firmware")  {
  if(version =~ "^V200R005C20" || version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007C00SPCb00")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPCb00");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:antiddos8000_firmware")  {
  if(version =~ "^V500R001C00" || version =~ "^V500R001C20SPC200" || version =~ "^V500R001C20SPC300" || version =~ "^V500R001C20SPC500" || version =~ "^V500R001C20SPC600") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6300_firmware")  {
  if(version =~ "^V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6600_firmware")  {
  if(version =~ "^V500R001C30") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC200")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC200");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}
else if (cpe == "cpe:/o:huawei:usg6000v_firmware")  {
  if(version =~ "^V500R001C10" || version =~ "^V500R001C10SPC100") {
    if (!patch || version_is_less(version: patch, test_version: "V500R005C00SPC100")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C00SPC100");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);

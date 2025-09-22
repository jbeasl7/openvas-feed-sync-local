# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143948");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-05-20 06:07:09 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability (huawei-sa-20160824-01-ipv6)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to a denial of service vulnerability in
  the IPv6 Neighbor Discovery packet process.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a vulnerability in the IP Version 6 (IPv6) Neighbor Discovery
  packet process of multiple products, successful exploit could allow an unauthenticated, remote attacker to
  cause an affected device to start dropping legitimate IPv6 neighbors, leading to a denial of service (DoS).");

  script_tag(name:"impact", value:"Successful exploit could allow an unauthenticated, remote attacker to cause
  an affected device to start dropping legitimate IPv6 neighbors leading to DOS.");

  script_tag(name:"affected", value:"Huawei AR120, AR150, AR160, AR200, AR500, AR510, AR1200, AR2200, AR3200,
  AR3600, CloudEngine 12800, CloudEngine 5800, CloudEngine 6800, CloudEngine 7800, CloudEngine 8800, S12700,
  S2300, S2700, S3300, S3700, S5300, S5700, S6300, S6700, S7700, S9300 and S9700.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160824-01-ipv6-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar120_firmware",
                     "cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar500_firmware",
                     "cpe:/o:huawei:ar510_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware",
                     "cpe:/o:huawei:s12700_firmware",
                     "cpe:/o:huawei:s2300_firmware",
                     "cpe:/o:huawei:s2700_firmware",
                     "cpe:/o:huawei:s3300_firmware",
                     "cpe:/o:huawei:s3700_firmware",
                     "cpe:/o:huawei:s5300_firmware",
                     "cpe:/o:huawei:s5700_firmware",
                     "cpe:/o:huawei:s6300_firmware",
                     "cpe:/o:huawei:s6700_firmware",
                     "cpe:/o:huawei:s7700_firmware",
                     "cpe:/o:huawei:s9300_firmware",
                     "cpe:/o:huawei:s9700_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:ar") {
  if (version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R006C10" || version =~ "^V200R007C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R007C00SPC900");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:cloudengine_(128|68)00") {
  if (version =~ "^V100R001C00" || version =~ "^V100R001C01" || version =~ "^V100R002C00" || version =~ "^V100R003C00" ||
      version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware") {
  if (version =~ "^V100R001C00" || version =~ "^V100R001C01" || version =~ "^V100R002C00" || version =~ "^V100R003C00" ||
      version =~ "^V100R003C10" || version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware") {
  if (version =~ "^V100R003C00" || version =~ "^V100R003C10" || version =~ "^V100R005C00" ||
      version =~ "^V100R005C10" || version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware") {
  if (version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s12700_firmware") {
  if (version =~ "^V200R005C00" || version =~ "^V200R006C00" || version =~ "^V200R007C00" ||
      version =~ "^V200R008C00" || version =~ "^V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s(23|27|33|37)00_firmware") {
  if (version =~ "^V100R006C05") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V100R006SPH028");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:s5300_firmware") {
  if (version =~ "^V200R002C00" || version =~ "^V200R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH012");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s5700_firmware") {
  if (version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH012");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s(63|67)00_firmware") {
  if (version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C00SPC500", fixed_patch: "V200R005SPH012");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R007C00" || version =~ "^V200R008C00" || version =~ "^V200R009C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:huawei:s(77|93|97)00_firmware") {
  if (version =~ "^V200R002C00" || version =~ "^V200R003C00" || version =~ "^V200R005C00" ||
      version =~ "^V200R006C00" || version =~ "^V200R007C00" || version =~ "^V200R008C00" ||
      version =~ "^V200R009C00") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_patch: "V200R009C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

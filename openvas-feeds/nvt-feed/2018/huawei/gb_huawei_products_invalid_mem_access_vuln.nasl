# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113195");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-24 12:32:45 +0200 (Thu, 24 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-06 13:29:00 +0000 (Wed, 06 Jun 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17314");

  script_name("Huawei Products Invalid Memory Access Vulnerability (huawei-sa-20180425-02-buffer)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei Switches are prone to an invalid memory access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated attacker can send malformed SCCP messages to the host.
  Due to insufficient input validation of some values in the messages, buffer errors can be caused.");

  script_tag(name:"impact", value:"Successful exploitation could lead to Denial of Service or execution of arbitrary code.");

  script_tag(name:"affected", value:"The following products and firmware versions are affected:

  - DP300: V500R002C00

  - RP200: V600R006C00

  - TE30 / TE60: V100R001C10, V500R002C00, V600R006C00

  - TE40 / TE50: V500R002C00, V600R006C00");

  script_tag(name:"solution", value:"The following device/firmware combinations contain a fix:

  - DP300: V500R002C00SPCb00

  - RP200 / TE30 / TE40 / TE50 / TE60: V600R006C00SPC500");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180425-02-buffer-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:dp300_firmware",
                     "cpe:/o:huawei:rp200_firmware",
                     "cpe:/o:huawei:te30_firmware",
                     "cpe:/o:huawei:te60_firmware",
                     "cpe:/o:huawei:te40_firmware",
                     "cpe:/o:huawei:te50_firmware"
                     );

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:huawei:dp300_firmware") {
  if (version == "V500R002C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R002C00SPCb00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:rp200_firmware") {
  if (version == "V600R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V600R006C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:te30_firmware" || cpe == "cpe:/o:huawei:te60_firmware") {
  if (version == "V100R001C10" || version == "V500R002C00" || version == "V600R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V600R006C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:te40_firmware" || cpe == "cpe:/o:huawei:te50_firmware") {
  if (version == "V500R002C00" || version == "V600R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V600R006C00SPC500");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

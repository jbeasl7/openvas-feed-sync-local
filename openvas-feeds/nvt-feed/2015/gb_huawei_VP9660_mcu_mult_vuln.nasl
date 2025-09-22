# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:huawei:vp_9660_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806637");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-01 12:03:03 +0530 (Tue, 01 Dec 2015)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2015-8227");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei VP9660 Multi-Point Control Unit Multiple Vulnerabilities (huawei-sa-20151111-01-vp9660)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_VP9660_mcu_detect.nasl");
  script_mandatory_keys("huawei/mcu/detected");

  script_tag(name:"summary", value:"Huawei VP9660 Multi-Point Control Unit is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as the server of the
  Huawei VP9660 does not validate the input when using built-in web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to log in to the device as a business administrator, graft a message
  to change the specific information, and send them to the server to inject
  malicious commands, leading to information leakage or device unavailability.");

  script_tag(name:"affected", value:"Huawei VP9660 Multi-Point Control Unit
  versions V200R001C01, V200R001C02 and V200R001C30 are affected.");

  script_tag(name:"solution", value:"Upgrade to version V200R001C30SPC700 or later.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/hw-461216");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!vers = toupper(get_app_version(cpe: CPE, nofork: TRUE)))
  exit(0);

if (vers =~ "^V200R001C01" || vers =~ "^V200R001C02" ||
    (vers =~ "^V200R001C30" && version_is_less(version: vers, test_version: "V200R001C30SPC700"))) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"V200R001C30SPC700");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

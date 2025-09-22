# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quickheal:antivirus_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811549");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8773", "CVE-2017-8774", "CVE-2017-8775", "CVE-2017-8776");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-13 12:05:00 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-08-02 12:24:09 +0530 (Wed, 02 Aug 2017)");
  script_name("Quick Heal Anti-Virus Pro Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Quick Heal Anti-Virus Pro is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The PE files in the default installation do not use ASLR/DEP protection
    mechanisms that provide sufficient defense against directed attacks against
    the product.

  - A Memory Corruption error while parsing a malformed Mach-O file.

  - An Out of Bounds Write on a Heap Buffer due to improper validation of
    dwCompressionSize of Microsoft WIM Header WIMHEADER_V1_PACKED.

  - A Memory Corruption error while parsing a malformed Mach-O file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain Remote Code Execution as well as Privilege Escalation.");

  script_tag(name:"affected", value:"Quick Heal AntiVirus Pro 10.1.0.316
  and prior.");

  script_tag(name:"solution", value:"The vendor has released multiple patches to fix the vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.quickheal.co.in/quick-heal-antivirus-updates-download/");
  script_xref(name:"URL", value:"http://payatu.com/quick-heal-antivirus-protection-mechanism-failure-vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_quick_heal_av_detect.nasl");
  script_mandatory_keys("QuickHeal/Antivirus6432/Pro/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"10.1.0.316")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(data:report);
  exit(0);
}

exit(99);

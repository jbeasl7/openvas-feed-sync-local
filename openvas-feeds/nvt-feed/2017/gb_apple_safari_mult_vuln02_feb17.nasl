# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810565");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-7650", "CVE-2016-4692", "CVE-2016-7635", "CVE-2016-7652",
                "CVE-2016-7656", "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587",
                "CVE-2016-7610", "CVE-2016-7611", "CVE-2016-7639", "CVE-2016-7640",
                "CVE-2016-7641", "CVE-2016-7642", "CVE-2016-7645", "CVE-2016-7646",
                "CVE-2016-7648", "CVE-2016-7649", "CVE-2016-7654", "CVE-2016-7589",
                "CVE-2016-7592", "CVE-2016-7598", "CVE-2016-7599", "CVE-2016-7623",
                "CVE-2016-7632");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-22 14:46:57 +0530 (Wed, 22 Feb 2017)");
  script_name("Apple Safari Multiple Vulnerabilities-02 (Feb 2017)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple validation issues in Safari Reader component.

  - Multiple memory corruption issues in WebKit.

  - A validation issue in state management.

  - An issue existed in handling of JavaScript prompts.

  - An uninitialized memory access issue in WebKit.

  - An issue existed in the handling of HTTP redirects in WebKit.

  - An issue existed in the handling of blob URLs in WebKit.

  - Multiple memory corruption issues in WebKit.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct UXSS attacks, execute arbitrary code or cause a denial
  of service, disclose sensitive information and can cause an unexpected
  application termination.");

  script_tag(name:"affected", value:"Apple Safari versions before 10.0.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 10.0.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207421");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"10.0.2"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10.0.2");
  security_message(data:report);
  exit(0);
}

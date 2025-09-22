# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810564");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2017-2359", "CVE-2017-2350", "CVE-2017-2362", "CVE-2017-2373",
                "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2366",
                "CVE-2017-2369", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-02-22 14:46:57 +0530 (Wed, 22 Feb 2017)");
  script_name("Apple Safari Multiple Vulnerabilities-01 (Feb 2017)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A state management issue in the address bar.

  - A prototype access issue in WebKit

  - Multiple memory corruption issues in WebKit.

  - A memory initialization issue in WebKit.

  - Multiple validation issues existed in the handling of page loading in WebKit.

  - A validation issue existed in variable handling in WebKit.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof the address bar, bypass security restrictions and obtain
  sensitive information, execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Safari versions before 10.0.3");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 10.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207484");
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

if(version_is_less(version:safVer, test_version:"10.0.3"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10.0.3");
  security_message(data:report);
  exit(0);
}

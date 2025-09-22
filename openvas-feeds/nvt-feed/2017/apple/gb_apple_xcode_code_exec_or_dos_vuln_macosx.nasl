# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811966");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-7076", "CVE-2017-7137", "CVE-2017-7136", "CVE-2017-7135",
                "CVE-2017-7134", "CVE-2017-9800", "CVE-2017-1000117");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-11-03 12:56:08 +0530 (Fri, 03 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Code Execution or Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"Apple Xcode is prone to code execution or denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - An input validation issue.

  - An ssh:// URL scheme handling issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 9.0");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100259");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100249");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!xcVer = get_app_version(cpe:CPE)){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");

if(version_is_greater_equal(version:osVer, test_version:"10.12.6"))
{
  if(version_is_less(version:xcVer, test_version:"9.0"))
  {
    report = report_fixed_ver(installed_version:xcVer, fixed_version:"9.0");
    security_message(data:report);
    exit(0);
  }
}

exit(99);

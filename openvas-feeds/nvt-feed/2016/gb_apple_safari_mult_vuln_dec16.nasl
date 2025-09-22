# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810225");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-4589", "CVE-2016-4622", "CVE-2016-4623", "CVE-2016-4624",
                "CVE-2016-4586", "CVE-2016-4583", "CVE-2016-4592", "CVE-2016-4591",
                "CVE-2016-4590", "CVE-2016-4651", "CVE-2016-4585", "CVE-2016-4584");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:04:00 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-12-01 13:55:02 +0530 (Thu, 01 Dec 2016)");
  script_name("Apple Safari Multiple Vulnerabilities (Dec 2016) - Mac OS X");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - multiple errors in WebKit Page Loading implementation

  - an error in WebKit JavaScript bindings

  - WebKit mishandles about: URLs, location variable

  - some unspecified errors in WebKit");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass security and execute
  arbitrary code or cause a denial of service.");

  script_tag(name:"affected", value:"Apple Safari versions before 9.1.2.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 9.1.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91830");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:safVer, test_version:"9.1.2")) {
  report = report_fixed_ver(installed_version:safVer, fixed_version:"9.1.2");
  security_message(data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807889");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-4618", "CVE-2016-4751", "CVE-2016-4728", "CVE-2016-4758",
                "CVE-2016-4611", "CVE-2016-4729", "CVE-2016-4730", "CVE-2016-4731",
                "CVE-2016-4734", "CVE-2016-4735", "CVE-2016-4737", "CVE-2016-4759",
                "CVE-2016-4762", "CVE-2016-4766", "CVE-2016-4767", "CVE-2016-4768",
                "CVE-2016-4769", "CVE-2016-4760", "CVE-2016-4733", "CVE-2016-4765",
                "CVE-2016-4763");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 19:30:00 +0000 (Tue, 12 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-09-28 12:58:27 +0530 (Wed, 28 Sep 2016)");
  script_name("Apple Safari Multiple Vulnerabilities (Sep 2016) - Mac OS X");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A state management issue in the handling of tab sessions.

  - Multiple input validation issues.

  - A parsing issue in the handling of error prototypes.

  - A permissions issue in the handling of the location variable.

  - Multiple memory corruption issues.

  - An error in safari's support of HTTP/0.9.

  - A certificate validation issue in the handling of WKWebView.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks, spoofing attacks, arbitrary
  code execution, access to potentially sensitive data, intercept and alter
  network traffic.");

  script_tag(name:"affected", value:"Apple Safari versions before 10");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 10 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93064");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93058");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:safVer, test_version:"10"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10");
  security_message(data:report);
  exit(0);
}



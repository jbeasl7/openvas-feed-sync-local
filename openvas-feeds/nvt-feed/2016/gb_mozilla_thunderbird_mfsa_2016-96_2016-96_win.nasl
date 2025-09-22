# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809844");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-9899", "CVE-2016-9895", "CVE-2016-9897", "CVE-2016-9898",
                "CVE-2016-9900", "CVE-2016-9904", "CVE-2016-9905", "CVE-2016-9893");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 17:55:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"creation_date", value:"2016-12-29 11:39:06 +0530 (Thu, 29 Dec 2016)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2016-96, MFSA2016-96) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An Use-after-free while manipulating DOM events and audio elements.

  - A CSP bypass using marquee tag.

  - The Memory corruption in libGLES.

  - An Use-after-free in Editor while manipulating DOM subtrees.

  - A Restricted external resources can be loaded by SVG images through data URLs.

  - A Cross-origin information leak in shared atoms.

  - A Crash in EnumerateSubDocuments.

  - Other Memory Corruption Errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to steal cookie-based authentication credentials, bypass certain
  security restrictions, obtain sensitive information and execute arbitrary
  code in the context of the affected application. Failed exploit attempts
  will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 45.6 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird 45.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-96");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94884");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"45.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.6");
  security_message(data:report);
  exit(0);
}

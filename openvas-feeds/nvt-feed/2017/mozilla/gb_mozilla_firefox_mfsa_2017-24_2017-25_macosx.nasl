# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811350");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7831", "CVE-2017-7832",
                "CVE-2017-7833", "CVE-2017-7834", "CVE-2017-7835", "CVE-2017-7836",
                "CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7839", "CVE-2017-7840",
                "CVE-2017-7842", "CVE-2017-7827", "CVE-2017-7826");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-25 18:47:00 +0000 (Mon, 25 Jun 2018)");
  script_tag(name:"creation_date", value:"2017-11-16 12:42:13 +0530 (Thu, 16 Nov 2017)");
  script_name("Mozilla Firefox Security Advisories (MFSA2017-24, MFSA2017-25) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free of PressShell while restyling layout.

  - Cross-origin URL information leak through Resource Timing API.

  - Information disclosure of exposed properties on JavaScript proxy objects.

  - Domain spoofing through use of dotless character followed by accent markers.

  - Domain spoofing with Arabic and Indic vowel marker characters.

  - Data: URLs opened in new tabs bypass CSP protections.

  - Mixed content blocking incorrectly applies with redirects.

  - Pingsender dynamically loads libcurl on Linux and OS X.

  - SVG loaded as can use meta tags to set cookies.

  - Failure of individual decoding of labels in international domain names triggers punycode display of entire IDN.

  - Control characters before javascript: URLs defeats self-XSS prevention mechanism.

  - Exported bookmarks do not strip script elements from user-supplied tags.

  - Referrer Policy is not always respected for elements.

  - Memory safety bugs fixed in Firefox 57.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  to execute arbitrary code, bypass security restrictions, perform unauthorized
  actions, and obtain sensitive information. Failed exploit attempts will likely
  result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 57.0 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 57.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-24/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101832");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"57.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);

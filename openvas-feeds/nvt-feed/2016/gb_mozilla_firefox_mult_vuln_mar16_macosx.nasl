# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807521");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1957", "CVE-2016-1958",
                "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1950", "CVE-2016-1952",
                "CVE-2016-1953", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963",
                "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967",
                "CVE-2016-1968", "CVE-2016-1969", "CVE-2016-1973", "CVE-2016-1974",
                "CVE-2016-1977", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791",
                "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795",
                "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799",
                "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-03-14 18:18:51 +0530 (Mon, 14 Mar 2016)");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Mar 2016) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The 'nsCSPContext::SendReports' function in 'dom/security/nsCSPContext.cpp'
    script does not prevent use of a non-HTTP report-uri for a CSP violation
    report.

  - The CSP violation reports contained full path information for cross-origin
    iframe navigations in violation of the CSP specification.

  - A memory leak in the libstagefright library when array destruction occurs
    during MPEG4 video file processing.

  - An error in 'browser/base/content/browser.js' script.

  - Multiple use-after-free issues.

  - Multiple out-of-bounds read errors

  - A memory corruption vulnerability in the FileReader class.

  - The mishandling of a navigation sequence that returns to the original page.

  - Improper restriction of the availability of IFRAME Resource Timing API times.

  - Integer underflow in Brotli library's decompression.

  - A memory corruption issue in NPAPI plugin in 'nsNPObjWrapper::GetNewOrUsed'
    function in 'dom/plugins/base/nsJSNPRuntime.cpp' script.

  - A race condition in the 'GetStaticInstance' function in the WebRTC
    implementation.

  - Multiple Heap-based buffer overflow vulnerabilities.

  - The multiple unspecified vulnerabilities in the browser engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or to cause a denial of service,
  possibly gain privileges, to bypass the Same Origin Policy, to obtain
  sensitive information and to do spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 45.0 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 45.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-22");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-25");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-19");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.0");
  security_message(data:report);
  exit(0);
}

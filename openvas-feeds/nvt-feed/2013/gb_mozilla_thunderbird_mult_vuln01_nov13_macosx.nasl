# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804139");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5603", "CVE-2013-5604", "CVE-2013-5602", "CVE-2013-5601",
                "CVE-2013-5600", "CVE-2013-5599", "CVE-2013-5597", "CVE-2013-5591",
                "CVE-2013-5590", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-11-07 19:08:51 +0530 (Thu, 07 Nov 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 (Nov 2013) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 24.1 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Use-after-free vulnerability in the
'nsContentUtils::ContentIsHostIncludingDescendantOf' function.

  - Improper data initialization in the 'txXPathNodeUtils::getBaseURI' function.

  - An error in 'Worker::SetEventListener' function in the Web workers
implementation.

  - Use-after-free vulnerability in the 'nsEventListenerManager::SetEventHandler'
function.

  - Use-after-free vulnerability in 'nsIOService::NewChannelFromURIWithProxyFlags'
function.

  - Use-after-free vulnerability in the 'nsIPresShell::GetPresContext' function.

  - Use-after-free vulnerability in 'nsDocLoader::doStopDocumentLoad' function.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Improper restriction of the nature or placement of HTML within dropdown menu.

  - Improper memory allocation for unspecified functions by JavaScript engine.

  - Improper determination of the thread for release of an image object.");
  script_tag(name:"affected", value:"Mozilla Thunderbird before version 24.1 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service, spoof the address bar, conduct clickjacking attacks
and conduct buffer overflow attacks.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63422");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63430");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-102.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"24.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"24.1");
  security_message(port: 0, data: report);
  exit(0);
}

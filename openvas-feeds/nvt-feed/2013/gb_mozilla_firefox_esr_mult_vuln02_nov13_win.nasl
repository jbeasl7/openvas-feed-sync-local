# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804132");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5604", "CVE-2013-5602", "CVE-2013-5601", "CVE-2013-5600",
                "CVE-2013-5599", "CVE-2013-5597", "CVE-2013-5590", "CVE-2013-5595");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-11-07 14:28:51 +0530 (Thu, 07 Nov 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-02 (Nov 2013) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 17.0.10 or 24.1 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Improper data initialization in the 'txXPathNodeUtils::getBaseURI' function.

  - An error in 'Worker::SetEventListener' function in Web workers implementation.

  - Use-after-free vulnerability in the
'nsEventListenerManager::SetEventHandler' function.

  - Use-after-free vulnerability in 'nsIOService::NewChannelFromURIWithProxyFlags'
function.

  - Use-after-free vulnerability in the 'nsIPresShell::GetPresContext' function.

  - Use-after-free vulnerability in 'nsDocLoader::doStopDocumentLoad' function.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Improper memory allocation for unspecified functions by JavaScript engine.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version 17.x before 17.0.10 and 24.x before 24.1 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service and conduct buffer overflow attacks.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63422");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63430");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-96.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^(17\.0|24\.0)")
{
  if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.9") ||
     version_in_range(version:vers, test_version:"24.0", test_version2:"24.0.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

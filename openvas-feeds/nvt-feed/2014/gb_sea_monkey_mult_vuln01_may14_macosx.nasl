# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804569");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523",
                "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529",
                "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:26:00 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2014-05-06 16:15:38 +0530 (Tue, 06 May 2014)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 (May 2014) - Mac OS X");


  script_tag(name:"summary", value:"SeaMonkey is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error exists when handling Web Audio.

  - An error exists when validating the XBL status of an object.

  - A use-after-free error exists when processing HTML video in the Text Track
  Manager.

  - An error exists when handling site notifications within the Web Notification
  API.

  - An error exists when handling browser navigations through history to load a
  website.

  - A use-after-free error exists when handling an imgLoader object within the
  'nsGenericHTMLElement::GetWidthHeightForImage()' function.

  - An error exists in NSS.

  - A use-after-free error exists when handling host resolution within the
  'libxul.so!nsHostResolver::ConditionallyRefreshRecord()' function.

  - An error exists when handling the debugging of certain objects.

  - And some unspecified errors exist.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.");
  script_tag(name:"affected", value:"SeaMonkey version before 2.26 on Mac OS X");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.26 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67123");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67134");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67137");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.26"))
{
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.26");
  security_message(port:0, data:report);
  exit(0);
}

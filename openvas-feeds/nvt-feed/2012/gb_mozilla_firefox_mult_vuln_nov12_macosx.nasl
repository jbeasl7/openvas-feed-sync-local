# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803060");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-4203", "CVE-2012-5837");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-11-26 14:47:00 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Nov 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51358/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56645");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027792");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-95.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-102.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject script or execute
  arbitrary programs in the context of the browser.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 17.0 on Mac OS X");
  script_tag(name:"insight", value:"- An error within the 'Web Developer Toolbar' allows script to be executed
    in chrome privileged context.

  - The 'Javascript:' URLs when opened in a New Tab page inherits the
    privileges of the privileged 'new tab' page.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 17.0 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"17.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"17.0");
    security_message(port:0, data:report);
    exit(0);
  }
}

# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804131");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-5603", "CVE-2013-5598", "CVE-2013-5591", "CVE-2013-5593",
                "CVE-2013-5596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-11-07 12:28:51 +0530 (Thu, 07 Nov 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 (Nov 2013) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 24.1 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Use-after-free vulnerability in the
'nsContentUtils::ContentIsHostIncludingDescendantOf' function.

  - Improper handling of the appending of an IFRAME element in 'PDF.js'.

  - Unspecified vulnerabilities in the browser engine.

  - Improper restriction of the nature or placement of HTML within a dropdown
menu.

  - Improper determination of the thread for release of an image object.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version 24.x before 24.1 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service, spoof the address bar and conduct clickjacking
attacks.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55520/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63429");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-99.html");
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

if(vers && vers =~ "^24\.")
{
  if(version_is_less(version:vers, test_version:"24.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

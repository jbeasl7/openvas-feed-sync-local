# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805219");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-1594", "CVE-2014-1593", "CVE-2014-1592", "CVE-2014-1590",
                "CVE-2014-1587");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-12-16 10:53:05 +0530 (Tue, 16 Dec 2014)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 (Dec 2014) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A bad cast issue from the BasicThebesLayer to BasicContainerLayer.

  - An error when parsing media content within the 'mozilla::FileBlockCache::Read'
  function.

  - A use-after-free error when parsing certain HTML within the
  'nsHtml5TreeOperation' class.

  - An error that is triggered when handling JavaScript objects that are passed
  to XMLHttpRequest that mimics an input stream.

  - Multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  disclose potentially sensitive information, compromise a user's system and
  have other unknown impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR 31.x before 31.3 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 31.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60558");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71398");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-89");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-88");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^31\.")
{
  if((version_in_range(version:vers, test_version:"31.0", test_version2:"31.2")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

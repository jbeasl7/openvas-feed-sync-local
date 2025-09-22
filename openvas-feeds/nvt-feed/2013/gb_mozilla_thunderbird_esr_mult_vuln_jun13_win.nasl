# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903217");
  script_version("2025-03-05T05:38:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                "CVE-2013-1697", "CVE-2013-1682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-06-26 17:09:51 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities (Jun 2013) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60787");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028702");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible.");
  script_tag(name:"affected", value:"Thunderbird ESR versions 17.x before 17.0.7 on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - PreserveWrapper does not handle lack of wrapper.

  - Error in processing of SVG format images with filters to read pixel values.

  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.

  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.

  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.

  - XrayWrapper does not properly restrict use of DefaultValue for method calls.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird ESR 17.0.7 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird-ESR/Win/Ver");
if(vers && vers =~ "^17\.0")
{
  if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.6")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

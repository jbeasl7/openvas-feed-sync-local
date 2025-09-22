# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800636");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:03:54 +0000 (Fri, 02 Feb 2024)");
  script_cve_id("CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835",
                "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839",
                "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-1392", "CVE-2009-2061",
                "CVE-2009-2065");
  script_name("Mozilla Firefox Multiple Vulnerabilities (Jun 2009) - Windows");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35326");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35360");
  script_xref(name:"URL", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-28.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-29.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-30.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-31.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-32.html");
  script_xref(name:"URL", value:"http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary JavaScript code
  execution, spoofing attacks, sensitive information disclosure, and can cause
  denial of service.");

  script_tag(name:"affected", value:"Firefox version prior to 3.0.11 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are reported in Mozilla Firefox. Please see the references
  for more information on the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.11.");

  script_tag(name:"summary", value:"Firefox Browser is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(firefoxVer != NULL)
{
  if(version_is_less(version:firefoxVer ,test_version:"3.0.11")){
    report = report_fixed_ver(installed_version:firefoxVer, fixed_version:"3.0.11");
    security_message(port: 0, data: report);
  }
}

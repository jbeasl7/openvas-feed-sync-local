# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803381");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-1383", "CVE-2013-1384", "CVE-2013-1385", "CVE-2013-1386");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-04-19 10:32:08 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities -01 (Apr 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52981");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58982");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58983");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58984");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-12.html");
  script_xref(name:"URL", value:"http://cert-mu.gov.mu/English/Pages/Vulnerability%20Notes/2013/VN-2013-93.aspx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause obtain
  sensitive information, remote code execution, and corrupt system memory.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Version 12.0.0.112 and prior on Mac OS X");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Unknown errors in unspecified vectors.

  - Buffer overflow via unspecified vectors.

  - Does not prevent access to address information, which makes it easy to
    bypass the ASLR protection mechanism.");
  script_tag(name:"solution", value:"Upgrade to version 12.0.2.122 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Shockwave/MacOSX/Version");
if(vers) {
  if(version_is_less_equal(version:vers, test_version:"12.0.0.112"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 12.0.0.112");
    security_message(port: 0, data: report);
    exit(0);
  }
}

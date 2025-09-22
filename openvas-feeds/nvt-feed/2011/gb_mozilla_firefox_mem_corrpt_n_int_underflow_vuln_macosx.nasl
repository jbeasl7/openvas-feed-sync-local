# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802181");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-2996", "CVE-2011-2998");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Memory Corruption and Integer Underflow Vulnerabilities - Mac OS X");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49845");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  with the privileges of the user running the affected application. Failed
  attempts may trigger a denial-of-service condition.");
  script_tag(name:"affected", value:"Mozilla Firefox 3.6.x before 3.6.23");
  script_tag(name:"insight", value:"The flaws are due to

  - An integer underflow error exists within the Regular Expression engine
    when evaluating certain regular expressions.

  - An unspecified error can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.23 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to memory corruption and integer underflow vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.22")){
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.6.0 - 3.6.22");
    security_message(port: 0, data: report);
  }
}

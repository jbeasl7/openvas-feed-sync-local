# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800090");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503",
                "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510",
                "CVE-2008-5511", "CVE-2008-5512");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities (Dec 2008) - Windows");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32882");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, sensitive information disclosure, cross
  site scripting attacks and execute JavaScript code with chrome privileges.");

  script_tag(name:"affected", value:"Thunderbird version prior to 2.0.0.19 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Thunderbird version 2.0.0.19.");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(!tbVer){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"2.0.0.19")){
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"2.0.0.19");
  security_message(port: 0, data: report);
}

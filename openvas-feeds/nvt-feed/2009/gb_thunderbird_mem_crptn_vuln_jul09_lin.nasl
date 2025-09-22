# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900802");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464",
                "CVE-2009-2465", "CVE-2009-2466");
  script_name("Mozilla Thunderbird Memory Corruption Vulnerabilities (Jul 2009) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35775");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35776");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary code and / or
  to cause memory corruption. Both could result in a denial-of-service condition.");
  script_tag(name:"affected", value:"Mozilla Thunderbird version 2.0.0.22 and prior on Linux.");
  script_tag(name:"insight", value:"The flaws are due to errors in the browser engine which can be exploited
  via some of the known vectors and additional unspecified vectors.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 3 or later.");
  script_tag(name:"summary", value:"Thunderbird is prone to Remote Code Execution vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/Linux/Ver");
if(!vers){
  exit(0);
}

if(version_is_less_equal(version:vers, test_version:"2.0.0.22")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 2.0.0.22");
  security_message(port: 0, data: report);
}

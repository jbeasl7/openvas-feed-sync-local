# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801335");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-0127", "CVE-2010-0128", "CVE-2010-0129", "CVE-2010-0130",
                "CVE-2010-1280", "CVE-2010-1281", "CVE-2010-1282", "CVE-2010-1283",
                "CVE-2010-1284", "CVE-2010-1286", "CVE-2010-1287", "CVE-2010-1288",
                "CVE-2010-1289", "CVE-2010-1290", "CVE-2010-1291", "CVE-2010-1292",
                "CVE-2010-0987", "CVE-2010-0986");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-01 19:35:00 +0000 (Fri, 01 Apr 2022)");
  script_name("Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities (May 2010)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40079");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40096");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/shockwave_mem.txt");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1128");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-12.html");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4937.php");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-05/0139.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of the affected application by tricking a user into visiting a
  specially crafted web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.7.609 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are caused by memory corruption errors, integer and buffer
  overflows, array indexing, and signedness errors when processing malformed
  'Shockwave' or 'Director' files, which could be exploited by attackers to
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.7.609.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.7.609")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.7.609");
  security_message(port: 0, data: report);
}

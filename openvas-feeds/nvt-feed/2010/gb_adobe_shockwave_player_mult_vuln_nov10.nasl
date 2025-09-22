# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901167");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-2581", "CVE-2010-2582", "CVE-2010-3653", "CVE-2010-3655",
                "CVE-2010-4084", "CVE-2010-4085", "CVE-2010-4086", "CVE-2010-4087",
                "CVE-2010-4088", "CVE-2010-4089", "CVE-2010-4090");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Nov 2010)");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code by
  tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.9.615 on Windows");
  script_tag(name:"insight", value:"Multiple flaws are caused by memory corruptions and buffer overflow errors
  in the 'DIRAPI.dll' and 'IML32.dll' modules when processing malformed Shockwave
  or Director files.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.9.615");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44514");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44515");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44518");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44519");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44521");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-25.html");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.9.615")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.9.615");
  security_message(port: 0, data: report);
}

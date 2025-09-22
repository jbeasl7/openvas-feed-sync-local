# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800443");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4003", "CVE-2009-4002");
  script_name("Adobe Shockwave Player 3D Model Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-61/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37872");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0171");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023481.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-03.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509062/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful attack could allow attackers to execute arbitrary code and compromise
  a vulnerable system.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.6.606 on Windows.");
  script_tag(name:"insight", value:"These flaws are caused by buffer and integer overflow errors when processing
  Shockwave files or 3D models, which could be exploited to execute arbitrary
  code by tricking a user into visiting a specially crafted web page.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.6.606 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to buffer overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.6.606")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.6.606");
  security_message(port: 0, data: report);
}

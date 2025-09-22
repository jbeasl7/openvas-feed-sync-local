# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902237");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-2863", "CVE-2010-2864", "CVE-2010-2865", "CVE-2010-2866",
                "CVE-2010-2867", "CVE-2010-2868", "CVE-2010-2869", "CVE-2010-2870",
                "CVE-2010-2871", "CVE-2010-2872", "CVE-2010-2873", "CVE-2010-2874",
                "CVE-2010-2875", "CVE-2010-2876", "CVE-2010-2877", "CVE-2010-2878",
                "CVE-2010-2879", "CVE-2010-2880", "CVE-2010-2881", "CVE-2010-2882");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Aug 2010)");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-13");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-14");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-10-15");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-161/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513299/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513334/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of the affected application.");
  script_tag(name:"affected", value:"Adobe Shockwave Player prior to 11.5.8.612 on Windows");
  script_tag(name:"insight", value:"Multiple memory corruption vulnerabilities are present in the application.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player 11.5.8.612");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.8.612")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.8.612");
  security_message(port: 0, data: report);
}

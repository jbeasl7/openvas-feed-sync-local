# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802938");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2012-2043", "CVE-2012-2044", "CVE-2012-2045", "CVE-2012-2046",
                "CVE-2012-2047");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-08-20 12:36:45 +0530 (Mon, 20 Aug 2012)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Aug 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50283/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55031");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-17.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions 11.6.5.635 and prior on Windows");
  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors in the application.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.6.6.636 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less_equal(version:shockVer, test_version:"11.6.5.635")){
  report = report_fixed_ver(installed_version:shockVer, vulnerable_range:"Less than or equal to 11.6.5.635");
  security_message(port:0, data:report);
}

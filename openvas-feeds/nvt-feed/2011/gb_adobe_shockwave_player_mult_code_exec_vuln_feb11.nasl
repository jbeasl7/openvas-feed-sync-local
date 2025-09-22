# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801846");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-2587", "CVE-2010-2588", "CVE-2010-2589",
                "CVE-2010-4092", "CVE-2010-4093", "CVE-2010-4187",
                "CVE-2010-4188", "CVE-2010-4189", "CVE-2010-4190",
                "CVE-2010-4191", "CVE-2010-4192", "CVE-2010-4193",
                "CVE-2010-4194", "CVE-2010-4195", "CVE-2010-4196",
                "CVE-2010-4306", "CVE-2010-4307", "CVE-2011-0555",
                "CVE-2011-0556", "CVE-2011-0557", "CVE-2011-0569");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Multiple Remote Code Execution Vulnerabilities (Feb 2011)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46146");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-01.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code by
  tricking a user into visiting a specially crafted web page.");
  script_tag(name:"affected", value:"Adobe Shockwave Player Versions prior to 11.5.9.620 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are caused by input validation errors, memory corruptions,
  buffer and integer overflows, and use-after-free errors in the DIRAPI, IML32,
  TextXtra, 3d Asset, and Xtra.x32 modules when processing malformed Shockwave
  or Director files.");
  script_tag(name:"solution", value:"Upgrade to Adobe Shockwave Player version 11.5.9.620 or later.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple remote code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

if(version_is_less(version:shockVer, test_version:"11.5.9.620")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.9.620");
  security_message(port: 0, data: report);
}

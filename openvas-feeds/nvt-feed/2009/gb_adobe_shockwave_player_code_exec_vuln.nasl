# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900582");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1860");
  script_name("Adobe Shockwave Player RCE Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35469");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-08.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name:"impact", value:"Successful attack could allow attackers to execute arbitrary code via a
  specially crafted Adobe Director file.");
  script_tag(name:"affected", value:"Adobe Shockwave Player before 11.5.0.600 on Windows.");
  script_tag(name:"insight", value:"The flaw exists when processing crafted Shockwave Player 10 content, and this
  can be exploited to cause memory corruption.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 11.5.0.600.");
  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer)
  exit(0);

if(version_is_less(version:shockVer, test_version:"11.5.0.600")){
  report = report_fixed_ver(installed_version:shockVer, fixed_version:"11.5.0.600");
  security_message(port: 0, data: report);
}

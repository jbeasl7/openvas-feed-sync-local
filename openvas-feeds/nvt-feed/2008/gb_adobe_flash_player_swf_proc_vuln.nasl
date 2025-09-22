# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800087");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-19 13:40:09 +0100 (Fri, 19 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5499");
  script_name("Adobe Flash Player for Linux SWF Processing Vulnerability");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-24.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  script_tag(name:"impact", value:"Successful attack could result in execution of arbitrary code on the remote
  affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 9.0.152.0/10.0.15.3 on Linux.");

  script_tag(name:"insight", value:"The issue is due to the way Flash Player handles the SWF files.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 9.0.152.0 or 10.0.15.3.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to Shockwave Flash (SWF) processing vulnerabilities.");

  exit(0);
}

include("version_func.inc");

adobeVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!adobeVer){
  exit(0);
}
# Version match 9.0 to 9.0.151.0 and 10.0 to 10.0.12.36
if(version_in_range(version:adobeVer, test_version:"9.0", test_version2:"9.0.151.0")) {
  report = report_fixed_ver(installed_version:adobeVer, vulnerable_range:"9.0 - 9.0.151.0");
  security_message(port: 0, data: report);
}
else if(version_in_range(version:adobeVer, test_version:"10.0", test_version2:"10.0.12.36")) {
  report = report_fixed_ver(installed_version:adobeVer, vulnerable_range:"10.0 - 10.0.12.36");
  security_message(port: 0, data: report);
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800420");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:21:08 +0000 (Sat, 03 Feb 2024)");
  script_cve_id("CVE-2010-0378", "CVE-2010-0379");
  script_name("Adobe Flash Player < 10.0.42.34 Remote Code Execution Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/27105");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2007-77/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023435.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/979267.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.");
  script_tag(name:"affected", value:"Adobe Flash Player 6.x on Windows XP.");
  script_tag(name:"insight", value:"The flaw is due to a use-after-free error in the bundled version of Flash
  Player when unloading Flash objects while these are still being accessed using
  script code.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 10.0.42.34.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to a remote code execution (RCE) vulnerability.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( vers =~ "^6\." ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.0.42.34", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

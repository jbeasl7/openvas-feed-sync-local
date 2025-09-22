# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903002");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-1264");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-21 16:45:16 +0530 (Wed, 21 Mar 2012)");
  script_name("GOM Media Player 'AVI' File Unspecified Vulnerability - Windows");
  script_xref(name:"URL", value:"http://gom.gomtv.com/gomIntro.html?type=4");
  script_xref(name:"URL", value:"http://www.exploitsearch.net/index.php?q=NVD+CVE-2012-1264");
  script_xref(name:"URL", value:"http://www.security-database.com/cvss.php?alert=CVE-2012-1264");
  script_xref(name:"URL", value:"http://heapoverflow.com/f0rums/advisories/29716-cve-2012-1264-gom_media_player.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_mandatory_keys("GOM/Player/Ver/Win");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application.");
  script_tag(name:"affected", value:"GOM Media Player version prior to 2.1.37.5091 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error, which allows remote attackers
  to execute arbitrary code via a crafted AVI file.");
  script_tag(name:"solution", value:"Upgrade to GOM Media Player 2.1.37.5091 or later.");
  script_tag(name:"summary", value:"GOM Media Player is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.gomlab.com/eng/");
  exit(0);
}


include("version_func.inc");

gomVer = get_kb_item("GOM/Player/Ver/Win");
if(!gomVer){
  exit(0);
}

if(version_is_less(version:gomVer, test_version:"2.1.37.5091")){
  report = report_fixed_ver(installed_version:gomVer, fixed_version:"2.1.37.5091");
  security_message(port:0, data:report);
}

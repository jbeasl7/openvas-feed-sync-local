# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900336");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1331");
  script_name("Microsoft Windows Media Player MID File Integer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8445");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will lets attacker execute arbitrary codes in
  the context of the affected player and can cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows Media Player version 11.0.5721.5145 and prior.");

  script_tag(name:"insight", value:"This flaw is due to a boundary checking error while processing mid files
  in Windows Media Player application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Windows Media Player is prone to an integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable"); # Plugin may results to Fp
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

wmplayerVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmplayerVer){
  exit(0);
}

if(version_is_less_equal(version:wmplayerVer, test_version:"11.0.5721.5145")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

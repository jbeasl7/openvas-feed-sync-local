# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902781");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-27 18:30:35 +0530 (Tue, 27 Dec 2011)");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_name("Windows Media Player Denial Of Service Vulnerability");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service.");

  script_tag(name:"affected", value:"Microsoft Windows Media Player version 11.0.5721.5262.");

  script_tag(name:"insight", value:"The flaw is caused to unspecified error in the application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Windows Media Player is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108152/wmp11-dos.txt");
  exit(0);
}

include("version_func.inc");

wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

if(version_is_equal(version:wmpVer, test_version:"11.0.5721.5262")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800480");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-02 12:36:32 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0718");
  script_name("Microsoft Windows Media Player '.mpg' Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56435");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11531");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will lets attacker execute arbitrary codes in
  the context of the affected player.");

  script_tag(name:"affected", value:"Microsoft Windows Media Player version 9.x and 11 to 11.0.5721.5145.");

  script_tag(name:"insight", value:"This flaw is due to a boundary checking error while opening a
  specially-crafted '.mpg' audio files.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Windows Media Player is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

wmpVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmpVer){
  exit(0);
}

if(wmpVer =~ "^(9|11)\..*$")
{
  if(version_in_range(version:wmpVer, test_version:"9.0", test_version2:"9.0.0.4503") ||
     version_in_range(version:wmpVer, test_version:"11.0", test_version2:"11.0.5721.5145")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

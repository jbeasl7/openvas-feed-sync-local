# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800729");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4097");
  script_name("Serenity/Mplay Audio Player Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/27998");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0911-exploits/serenityaudio-overflow.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_serenity_player_detect.nasl");
  script_mandatory_keys("Serenity/Audio/Player/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow local/remote attackers to trick the user
  to access the crafted m3u playlist file, execute the crafted shellcode into the
  context of the affected system memory registers to take control of the machine
  running the affected application.");
  script_tag(name:"affected", value:"Serenity/Mplay Audio Player 3.2.3.0 and prior on Windows.");
  script_tag(name:"insight", value:"There exists a stack overflow vulnerability within the 'MplayInputFile()'
  function in 'src/plgui.c' that fails to sanitize user input while the user
  crafts his/her own malicious playlist 'm3u' file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Serenity/Mplay Audio Player is prone to a code execution vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

if(appVer  = get_kb_item("Serenity/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer, test_version:"3.2.3.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(appVer2 = get_kb_item("Mplay/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer2, test_version:"3.2.3.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800571");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sonic Spot Audioactive Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"This script detects the version of Sonic Spot Audioactive Player.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Sonic Spot Audioactive Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}
key = "SOFTWARE\Telos Systems\Audioactive Player";
if(!registry_key_exists(key:key))exit(0);

foreach item (registry_enum_keys(key:key))
{
  audioactiveVer = eregmatch(pattern:"[0-9.]+[a-z]?", string:item);
  if(audioactiveVer != NULL)
  {
    set_kb_item(name:"SonicSpot/Audoiactive/Player/Ver", value:audioactiveVer[0]);

    register_and_report_cpe(app:"Sonic Spot Audioactive Player", ver:audioactiveVer[0],
                            base:"cpe:/a:sonicspot:audioactive_player:", expr:"^([0-9.]+([a-z0-9]+)?)");
    exit(0);
  }
}

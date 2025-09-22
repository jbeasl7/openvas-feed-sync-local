# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800592");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PeaZIP Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the installed PeaZIP version.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "PeaZIP Version Detection (Windows)";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}


if(!registry_key_exists(key:"SOFTWARE\PeaZip")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  peazipName = registry_get_sz(key:key + item, item:"DisplayName");
  if("PeaZip" >< peazipName)
  {
    peazipVer = eregmatch(pattern:"PeaZip ([0-9.]+[a-z]?)", string:peazipName);
    if(peazipVer[1] != NULL)
    {
      set_kb_item(name:"PeaZIP/Win/Ver", value:peazipVer[1]);
      log_message(data:"PeaZIP version " + peazipVer[1] +
                                  " was detected on the host");

      cpe = build_cpe(value:peazipVer[1], exp:"^([0-9.]+)", base:"cpe:/a:giorgio_tani:peazip:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}

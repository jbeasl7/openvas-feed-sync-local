# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800274");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("UltraISO Version Detection");

  script_category(ACT_GATHER_INFO);


  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of UltraISO.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "UltraISO Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ultraName = registry_get_sz(key:key + item, item:"DisplayName");
  if("UltraISO" >< ultraName)
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(path == NULL){
       continue;
    }

    v = GetVersionFromFile(file:path, offset:1174636);

    if(v != NULL)
    {
      set_kb_item(name:"UltraISO/Ver", value:v);
      cpe = build_cpe(value:v, exp:"^([0-9.]+)", base:"cpe:/a:ezbsystems:ultraiso:");
      if(!cpe)
        cpe = "cpe:/a:ezbsystems:ultraiso";

      register_product(cpe:cpe, location:path, port:0, service:"smb-login");
      log_message(data:build_detection_report(app:"UltraISO",
                                              version:v,
                                              install:path,
                                              cpe:cpe,
                                              concluded:v));
    }
    exit(0);
  }
}
exit(0);
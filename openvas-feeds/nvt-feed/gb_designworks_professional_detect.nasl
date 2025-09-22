# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800367");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("DesignWorks Professional Version Detection");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of DesignWorks
  Professional.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "DesignWorks Professional Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Capilano")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("DesignWorks Professional" ><
     registry_get_sz(key:key + item, item:"DisplayName"))
  {
    exePath = registry_get_sz(key:key + item, item:"UninstallString");
    exePath = eregmatch(pattern:"([A-Za-z0-9:.\]+) (.*)", string:exePath);

    if(exePath[2] == NULL){
      exit(0);
    }

    exePath = exePath[2] - "\uninstal.log" + "\System.dll";

    dwpVer = GetVersionFromFile(file:exePath, verstr="prod");

    if(dwpVer != NULL)
    {
      set_kb_item(name:"DesignWorks/Prof/Ver", value:dwpVer);

      cpe = build_cpe(value:dwpVer, exp:"^([0-9.]+)", base:"cpe:/a:capilano:designworks:");
      if(isnull(cpe))
        cpe = "cpe:/a:capilano:designworks";

      register_product(cpe: cpe, location: exePath, port:0, service:"smb-login");
      log_message(data: build_detection_report(app: "DesignWorks Professional",
                                             version: dwpVer,
                                             install: exePath,
                                                 cpe: cpe,
                                           concluded: dwpVer));

    }
    exit(0);
  }
}

exit(0);
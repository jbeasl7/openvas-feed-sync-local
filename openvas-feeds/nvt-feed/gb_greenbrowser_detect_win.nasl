# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803066");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-12-06 17:22:08 +0530 (Thu, 06 Dec 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("GreenBrowser Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Detects the installed version of GreenBrowser.

  The script logs in via smb, searches for GreenBrowser in the registry and
  gets the version from GreenBrowser.exe file using 'InstallLocation' string in registry");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item( registry_enum_keys( key:key ) )
{
  greenbName = registry_get_sz(key:key + item, item:"DisplayName");
  if("GreenBrowser" >< greenbName)
  {
    greenbPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(greenbPath)
    {

     greenbPath = greenbPath + "GreenBrowser.exe";
     greenbVer = GetVersionFromFile(file: greenbPath,verstr:"prod");

      if(greenbVer)
      {
        set_kb_item(name:"GreenBrowser/Win/Ver", value: greenbVer);

        cpe = build_cpe(value: greenbVer, exp:"^([0-9.]+)", base:"cpe:/a:morequick:greenbrowser:");
        if(isnull(cpe))
          cpe = 'cpe:/a:morequick:greenbrowser';

        register_product(cpe:cpe, location:greenbPath);

        log_message(data: build_detection_report(app: greenbName, version: greenbVer,
                                                 install: greenbPath, cpe:cpe, concluded:greenbVer));

        exit(0);
      }
    }
  }
}

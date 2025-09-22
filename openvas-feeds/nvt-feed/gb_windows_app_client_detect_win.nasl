# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836103");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-08 15:55:37 +0530 (Tue, 08 Apr 2025)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Windows App Client (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of Windows App Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("cpe.inc");

key = "SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("MicrosoftCorporationII.Windows365" >< item)
  {
    appPath = registry_get_sz(key:key + item, item:"Path");
    if("MicrosoftCorporationII.Windows365" >< appPath)
    {
      wacVer = eregmatch( pattern:"MicrosoftCorporationII.Windows365_([0-9.]+)_", string:appPath );
      if(wacVer)
      {
        set_kb_item(name:"WAClient/Win/Ver", value:wacVer[1]);
        set_kb_item(name:"WAClient/Win/detected", value:TRUE);

        register_and_report_cpe( app:"Windows App Client", ver:wacVer[1], concluded:wacVer[0],
                             base:"cpe:/a:microsoft:windows_app:", expr:"^([0-9.]+)",
                             insloc:appPath, regService:"smb-login", regPort:0 );
        exit(0);
      }
    }
  }
}

exit(0);

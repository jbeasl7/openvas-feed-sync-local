# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834528");
  script_version("2024-11-06T05:05:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-06 05:05:44 +0000 (Wed, 06 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-25 11:48:47 +0530 (Fri, 25 Oct 2024)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Web Media Extensions (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of Microsoft Web Media Extensions.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

key = "SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("Microsoft.WebMediaExtensions" >< item)
  {
    appPath = registry_get_sz(key:key + item, item:"Path");
    if("Microsoft.WebMediaExtensions" >< appPath)
    {
      webmediaextensionsVer = eregmatch( pattern:"Microsoft.WebMediaExtensions_([0-9.]+)_", string:appPath );
      if(webmediaextensionsVer)
      {
        set_kb_item(name:"WebMediaExtensions/Win/Ver", value:webmediaextensionsVer[1]);
        set_kb_item(name:"WebMediaExtensions/Win/detected", value:TRUE);

        register_and_report_cpe( app:"Microsoft Web Media Extensions", ver:webmediaextensionsVer[1], concluded:webmediaextensionsVer[0],
                             base:"cpe:/a:microsoft:web_media_extensions:", expr:"^([0-9.]+)",
                             insloc:appPath, regService:"smb-login", regPort:0 );
        exit(0);
      }
    }
  }
}

exit(0);

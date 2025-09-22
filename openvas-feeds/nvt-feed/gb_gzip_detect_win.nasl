# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800451");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("GZip Detection (Windows SMB Login)");


  script_tag(name:"summary", value:"Detects the installed version of GZip on Windows.

The script logs in via smb, searches for GZip in the registry
and gets the version from the registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!registry_key_exists(key:"SOFTWARE\GnuWin32\Gzip"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\GnuWin32\Gzip")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Gzip Wizard 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  gzipName = registry_get_sz(key:key + item, item:"DisplayName");

  if(" Gzip" >< gzipName)
  {
    gzipVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(gzipName != NULL)
    {
      appPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appPath){
        appPath = "Could not find the install Location from registry";
      }

      gzipVer = ereg_replace(pattern:"-", string:gzipVer, replace: ".");
      set_kb_item(name:"GZip/Win/Ver", value:gzipVer);

      cpe = build_cpe(value:gzipVer, exp:"^([0-9.]+)", base:"cpe:/a:gnu:gzip:");
      if(isnull(cpe))
        cpe = "cpe:/a:gnu:gzip";

      register_product(cpe:cpe, location:appPath);

      log_message(data: build_detection_report(app: gzipName,
                                               version: gzipVer,
                                               install: appPath,
                                               cpe: cpe,
                                               concluded: gzipName));
    }
  }
}

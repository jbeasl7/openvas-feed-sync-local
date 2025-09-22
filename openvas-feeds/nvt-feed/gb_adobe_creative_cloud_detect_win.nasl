# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807666");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-04-14 18:14:10 +0530 (Thu, 14 Apr 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detection of installed version
  of Adobe Creative Cloud Desktop Application on Windows.

  The script logs in via smb, searches for Adobe Creative Cloud in the registry
  and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

## if os is 32 bit iterate over common path
if("x86" >< osArch)
{
  cloud_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Creative Cloud\";
  key_enum = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

#currently 64 bit app is not available
else if("x64" >< osArch)
{
  cloud_key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Adobe Creative Cloud\";
  key_enum = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(registry_key_exists(key:cloud_key))
{
  ##Lets try to get version without enumerating all keys
  cclName = registry_get_sz(key:cloud_key, item:"DisplayName");
  if("Adobe Creative Cloud" >< cclName)
  {
    acc = TRUE;
    key = cloud_key;
  }
} else
{
  ##Enumerate over all keys
  foreach item (registry_enum_keys(key:key_enum))
  {
    cclName = registry_get_sz(key:key_enum + item, item:"DisplayName");
    if("Adobe Creative Cloud" >< cclName){
      acc_enum = TRUE;
      key = key_enum + item;
      break;
    }
  }
}

if(key)
{
  cclVer = registry_get_sz(key:key, item:"DisplayVersion");

  if(cclVer)
  {
    cclPath = registry_get_sz(key:key, item:"UninstallString");

    if(cclPath && "Utils" >< cclPath && "Creative Cloud Uninstaller" >< cclPath)
    {
      cclPath = cclPath - "Utils\Creative Cloud Uninstaller.exe";
      cclPath = ereg_replace(string: cclPath, pattern: '"', replace: "");
    } else if(!cclPath) {
      cclPath = "Could not find the install location from registry";
    }

    set_kb_item(name:"AdobeCreativeCloud/Win/Ver", value:cclVer);

    cpe = build_cpe(value:cclVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:creative_cloud:");
    if(!cpe)
      cpe = "cpe:/a:adobe:creative_cloud";

    register_product(cpe:cpe, location:cclPath);
    log_message(data: build_detection_report(app: "Adobe Creative Cloud",
                                             version: cclVer,
                                             install: cclPath,
                                             cpe: cpe,
                                             concluded: cclVer));
    exit(0);
  }
}

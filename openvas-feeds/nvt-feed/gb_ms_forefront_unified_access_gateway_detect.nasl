# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802746");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-13 10:46:45 +0530 (Fri, 13 Apr 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Forefront Unified Access Gateway (UAG) Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Forefront Unified Access Gateway.

The script logs in via smb, searches for Microsoft Forefront Unified Access
Gateway in the registry and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

# Application is available as 64 bit only and it can be
# installed only on 64 bit OS
# exit if its not 64 bit OS
# https://docs.microsoft.com/en-us/previous-versions/tn-archive/dd903051(v=technet.10)
if("x64" >!< os_arch){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  uagName = registry_get_sz(key:key + item, item:"DisplayName");

  if(!uagName){
    continue;
  }

  if("Microsoft Forefront Unified Access Gateway" >< uagName)
  {
    uagVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(uagVer)
    {
      set_kb_item(name:"MS/Forefront/UAG/Ver", value:uagVer);
      cpe = build_cpe(value:uagVer, exp:"^([0-9.]+)",
                    base:"cpe:/a:microsoft:forefront_unified_access_gateway:");

      insPath= 'Could not determine InstallLocation from Registry\n';
      if(cpe)
        register_product(cpe:cpe, location:insPath);

      log_message(data:'Detected MS Forefront Unified Access Gateway version: ' + uagVer +
                      '\nLocation: ' + insPath +
                      '\nCPE: '+ cpe +
                      '\n\nConcluded from version identification result:\n' +
                      'MS ForefrontUnified Access Gateway ' + uagVer);

    }
  }
}

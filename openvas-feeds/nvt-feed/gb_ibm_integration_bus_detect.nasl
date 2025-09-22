# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810801");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-03-23 16:40:33 +0530 (Thu, 23 Mar 2017)");
  script_name("IBM Integration Bus Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of IBM
  Integration Bus.

  The script logs in via smb, searches for 'IBM Integration Bus' string in the
  registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\IBM\IBM Integration Bus")){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  ibName = registry_get_sz(key:key + item, item:"DisplayName");

  if("IBM Integration Bus" >< ibName)
  {
    ibPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!ibPath){
      ibPath = "Could not find the install location from registry";
    }

    ibVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    ##If version is available
    if(ibVer)
    {
      set_kb_item(name:"IBM/Integration/Bus/Win/Ver", value:ibVer);

      cpe = build_cpe(value:ibVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:integration_bus:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:integration_bus";

      if("64" >< os_arch)
      {
        set_kb_item(name:"IBM/Integration/Bus/Win64/Ver", value:ibVer);

        cpe = build_cpe(value:ibVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:integration_bus:x64:");

        if(isnull(cpe))
          cpe = "cpe:/a:ibm:integration_bus:x64";
      }
      register_product(cpe:cpe, location:ibPath);
      log_message(data: build_detection_report(app: ibName,
                                               version: ibVer,
                                               install: ibPath,
                                               cpe: cpe,
                                               concluded: ibVer));
      exit(0);
    }
  }
}

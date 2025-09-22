# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801853");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Citrix License Server Version Detection");


  script_tag(name:"summary", value:"This script finds the installed Citrix License Server version.

  The script logs in via smb, searches for Citrix in the registry and gets the
  version from 'Version' string from the registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Citrix\LicenseServer\Install");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Citrix\LicenseServer\Install");
}

if(isnull(key_list)){
    exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Citrix\LicenseServer"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Citrix\LicenseServer"))
  {
    exit(0);
  }
}

foreach key (key_list)
{
  ciVer = registry_get_sz(key:key, item:"Version");

  if(ciVer)
  {
    ciPath = registry_get_sz(key:key, item:"LS_Install_Dir");
    if(!ciPath){
      ciPath = "Could not find the install location from registry";
    }

    set_kb_item(name:"Citrix/License/Server/Ver", value:ciVer);

    cpe = build_cpe(value:ciVer, exp:"^([0-9.]+)", base:"cpe:/a:citrix:licensing_administration_console:");
    if(isnull(cpe))
      cpe = "cpe:/a:citrix:licensing_administration_console";

    register_product(cpe:cpe, location:ciPath);
    log_message(data: build_detection_report(app: "Citrix License Server",
                                                 version:ciVer,
                                                 install: ciPath ,
                                                 cpe:cpe,
                                                 concluded:ciVer));
  }
}

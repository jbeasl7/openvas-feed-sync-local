# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900326");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("BitDefender Products Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of BitDefender products.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

key = "SOFTWARE\BitDefender";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\BitDefender";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\BitDefender\About\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\BitDefender\About\",
                        "SOFTWARE\Wow6432Node\BitDefender\About\");
}

foreach bitKey (key_list)
{
  bitName = registry_get_sz(key:bitKey, item:"ProductName");

  if("bitdefender internet security" >< tolower(bitName))
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");

    if(bitVer == NULL)
    {
      if("Wow6432Node" >< bitKey){
        key = "SOFTWARE\Wow6432Node\BitDefender\BitDefender Desktop\Maintenance\InternetSecurity";
      } else {
        key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\InternetSecurity";
      }

      bitVer = registry_get_sz(key:key, item:"ProductVersion");
    }

    if(bitVer)
    {
      insLoc = registry_get_sz(key:bitKey - 'About\\', item:"InstallDir");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"BitDefender/InetSec/Ver", value:bitVer);

      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:internet_security:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitdefender:internet_security";

      if("64" >< os_arch && "Wow6432Node" >!< bitKey)
      {
        set_kb_item(name:"BitDefender64/InetSec/Ver", value:bitVer);

        cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:internet_security:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bitdefender:internet_security:x64";
      }
      register_product(cpe:cpe, location:insLoc);
      log_message(data: build_detection_report(app:bitName, version:bitVer,
                                                 install:insLoc, cpe:cpe, concluded:bitVer));
    }
  }

  if("bitdefender antivirus" >< tolower(bitName))
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");

    if(bitVer == NULL)
    {
      if("Wow6432Node" >< bitKey){
        key = "SOFTWARE\Wow6432Node\BitDefender\BitDefender Desktop\Maintenance\Antivirus";
      } else {
        key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\Antivirus";
      }

      bitVer = registry_get_sz(key:key, item:"ProductVersion");
    }

    if(bitVer)
    {
      insLoc = registry_get_sz(key:bitKey - 'About\\', item:"InstallDir");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"BitDefender/AV/Ver", value:bitVer);

      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:bitdefender_antivirus:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitdefender:bitdefender_antivirus";

      if("64" >< os_arch && "Wow6432Node" >!< bitKey)
      {
        set_kb_item(name:"BitDefender64/AV/Ver", value:bitVer);

        cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:bitdefender_antivirus:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bitdefender:bitdefender_antivirus:x64";
      }
      register_product(cpe:cpe, location:insLoc);
      log_message(data: build_detection_report(app:bitName, version:bitVer,
                                                 install:insLoc, cpe:cpe, concluded:bitVer));
    }
  }

  if("bitdefender total security" >< tolower(bitName))
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");

    if(bitVer == NULL)
    {
      if("Wow6432Node" >< bitKey){
        key = "SOFTWARE\Wow6432Node\BitDefender\BitDefender Desktop\Maintenance\TotalSecurity";
      } else {
        key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\TotalSecurity";
      }

      bitVer = registry_get_sz(key:key, item:"ProductVersion");
    }

    if(bitVer)
    {
      insLoc = registry_get_sz(key:bitKey - 'About\\', item:"InstallDir");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"BitDefender/TotalSec/Ver", value:bitVer);

      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:total_security:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitdefender:total_security";

      if("64" >< os_arch && "Wow6432Node" >!< bitKey)
      {
        set_kb_item(name:"BitDefender64/InetSec/Ver", value:bitVer);

        cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:total_security:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bitdefender:total_security:x64";
      }

      register_product(cpe:cpe, location:insLoc);
      log_message(data: build_detection_report(app:bitName, version:bitVer,
                                                 install:insLoc, cpe:cpe, concluded:bitVer));
    }
  }
}

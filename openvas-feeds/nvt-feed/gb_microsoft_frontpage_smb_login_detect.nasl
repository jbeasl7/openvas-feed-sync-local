# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803891");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-11 11:32:12 +0530 (Wed, 11 Sep 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft FrontPage Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Microsoft FrontPage.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Office");
  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Office");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list && key_list2)){
  exit(0);
}


if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Office")){
    exit(0);
  }
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    if(eregmatch(pattern:"^([0-9.]+)" , string:item))
    {
      rootkey = key + "\" + item + "\FrontPage";
      if(!registry_key_exists(key: rootkey)){
        exit(0);
      }
      break;
    }
  }
}

foreach key (key_list2)
{
  foreach item (registry_enum_keys(key:key))
  {
    pageName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Microsoft Office FrontPage" >< pageName)
    {

      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc)
      {
        insloc = registry_get_sz(key: rootkey + "\InstallRoot", item:"Path");
        if(!insloc){
          # nb: The string is used in common/2013/gb_ms13-078.nasl
          insloc = "Unable to find the install location";
        }
      }

      vers = registry_get_sz(key:key + item, item:"DisplayVersion");
      set_kb_item(name:"microsoft/frontpage/detected", value:TRUE);
      set_kb_item(name:"microsoft/frontpage/smb-login/detected", value:TRUE);
      register_and_report_cpe(app:pageName, ver:vers, base:"cpe:/a:microsoft:frontpage:", expr:"^([0-9.]+)", insloc:insloc, regService:"smb-login", regPort:0);
    }
  }
}

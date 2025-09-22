# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806853");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-09 15:43:00 +0530 (Tue, 09 Feb 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Kaspersky Total Security Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Kaspersky Total security  on Windows.

  The script logs in via smb, searches for kaspersky in the registry, gets the
  kaspersky total security installation path from registry and fetches version.");

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

TOTALSEC_LIST = make_list( "^(15\..*)", "cpe:/a:kaspersky:total_security_2015:",
                           "^(16\..*)", "cpe:/a:kaspersky:total_security_2016:");
TOTALSEC_MAX = max_index(TOTALSEC_LIST);

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\KasperskyLab")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kaspersky Total Security" >< prdtName)
  {
      ktsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not determine install Path";
      }

      if(ktsVer != NULL)
      {
        set_kb_item(name:"Kaspersky/TotalSecurity/Ver", value:ktsVer);

        for (i = 0; i < TOTALSEC_MAX-1; i = i + 2)
        {
          register_and_report_cpe(app:"Kaspersky Total Security", ver:ktsVer, base:TOTALSEC_LIST[i+1],
                                  expr:TOTALSEC_LIST[i], insloc:insloc);
        }

      }
  }
}

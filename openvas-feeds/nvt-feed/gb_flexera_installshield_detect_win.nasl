# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809005");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-19 19:16:31 +0530 (Fri, 19 Aug 2016)");
  script_name("Flexera InstallShield Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Flexera InstallShield.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\InstallShield") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\InstallShield"))
  exit(0);

if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
else if("x64" >< os_arch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

if(isnull(key))
  exit(0);

TOTALSEC_LIST = make_list( "^(22\..+)", "cpe:/a:flexerasoftware:installshield_2015:",
                           "^(21\..+)", "cpe:/a:flexerasoftware:installshield_2014:",
                           "^(20\..+)", "cpe:/a:flexerasoftware:installshield_2013:");
TOTALSEC_MAX = max_index(TOTALSEC_LIST);

foreach item (registry_enum_keys(key:key)) {
  inshieldName = registry_get_sz(key:key + item, item:"DisplayName");

  if(inshieldName =~ "InstallShield( 2015| 2014| 2013)?$") {
    inshieldVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    inshieldPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!inshieldPath)
      inshieldPath = "Unable to find the install location from registry";

    if(inshieldVer) {
      set_kb_item(name:"Flexera/InstallShield/Win/Ver", value:inshieldVer);

      ## http://www.flexerasoftware.com/producer/support/additional-support/end-of-life/installshield.html
      for(i = 0; i < TOTALSEC_MAX-1; i = i + 2) {
        register_and_report_cpe(app:"Flexera InstallShield", ver:inshieldVer, base:TOTALSEC_LIST[i+1],
                                expr:TOTALSEC_LIST[i], insloc:inshieldPath);
      }
    }
  }
}

exit(0);

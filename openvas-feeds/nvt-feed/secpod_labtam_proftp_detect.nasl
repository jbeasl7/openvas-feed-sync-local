# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900979");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Labtam ProFTP Version Detection");

  script_tag(name:"summary", value:"This script detects the installed version of Labtam ProFTP.

The script logs in via smb, searches for ProFTP in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
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
  key_list = make_list("SOFTWARE\Lab-NC\ProFTP",
                       "SOFTWARE\Labtam\ProFtp");
  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ProFTP");

}
else if("x64" >< os_arch)
{
  ##For some versions the path is not coming like below.
  key_list =  make_list("SOFTWARE\Wow6432Node\Lab-NC\ProFTP",
                        "SOFTWARE\Wow6432Node\Labtam\ProFtp");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\ProFTP");
}

if(!registry_key_exists(key:"SOFTWARE\Lab-NC\ProFTP")){
  if(!registry_key_exists(key:"SOFTWARE\Labtam\ProFtp")){
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Lab-NC\ProFTP")){
      if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Labtam\ProFtp")){
        exit(0);
      }
    }
  }
}

if(isnull(key_list && key_list2)){
  exit(0);
}

foreach key (key_list)
{
  foreach item(registry_enum_keys(key:key))
  {
    if(item =~ "[0-9]\.[0-9]")
    {
      ftpVer = item;

      foreach key1 (key_list2)
      {
        ftpPath = registry_get_sz(key:key1, item:"Path");
        if(!ftpPath){
          ftpPath = "Could not find the install location from registry";
        }
      }

      if(ftpVer)
      {
        set_kb_item(name:"Labtam/ProFTP/Ver", value:ftpVer);

        cpe = build_cpe(value:item, exp:"^([0-9.]+)", base:"cpe:/a:labtam-inc:proftp:");
        if(isnull(cpe))
          cpe = "cpe:/a:labtam-inc:proftp:";

        register_product(cpe:cpe, location:ftpPath);
        log_message(data: build_detection_report(app: "Labtam ProFTP",
                                                 version:ftpVer,
                                                 install: ftpPath ,
                                                 cpe: cpe,
                                                 concluded:ftpVer));
      }
    }
  }
}

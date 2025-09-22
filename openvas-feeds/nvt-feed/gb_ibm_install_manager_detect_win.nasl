# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801010");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("IBM Installation Manager Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"The script detects the installed IBM Installation Manager version.

  The script logs in via smb, searches for IBM Installation Manager in the
  registry and gets the version from 'version' string in registry.");

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

checkduplicate = ""; # nb: To make openvas-nasl-lint happy...

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\IBM\Installation Manager");
}
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\IBM\Installation Manager",
                        "SOFTWARE\Wow6432Node\IBM\Installation Manager");
}

if(isnull(key_list)){
    exit(0);
}

foreach key (key_list)
{
  iimVer= registry_get_sz(key:key, item:"version");
  insloc= registry_get_sz(key:key, item:"appDataLocation");

  if(iimVer != NULL)
  {
    if (iimVer + ", " >< checkduplicate){
        continue;
    }

    checkduplicate += iimVer + ", ";

    set_kb_item(name:"IBM/InstallMang/Win/Ver", value:iimVer);

    cpe = build_cpe(value:iimVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:installation_manager:");
    if(isnull(cpe))
      cpe = "cpe:/a:ibm:installation_manager";

    if("64" >< os_arch && "Wow6432Node" >!< key)
    {
      set_kb_item(name:"IBM/InstallMang64/Win/Ver", value:iimVer);

      cpe = build_cpe(value:iimVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:installation_manager:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:installation_manager:x64";
    }
    register_product(cpe:cpe, location:insloc);
    log_message(data: build_detection_report(app: "IBM Installatin Manager",
                                             version: iimVer,
                                             install: insloc,
                                             cpe: cpe,
                                             concluded: iimVer));
  }
}

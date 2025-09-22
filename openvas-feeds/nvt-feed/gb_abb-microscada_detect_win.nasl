# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812815");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-03-05 17:50:51 +0530 (Mon, 05 Mar 2018)");
  script_name("ABB MicroSCADA Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"Detects the installed version of ABB
  MicroSCADA on Windows.

  The script logs in via smb, searches for MicroSCADA in the registry and
  gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = make_list("SOFTWARE\ABB\Products\SYS_600");
}

else if("x64" >< osArch){
  key_list =  make_list("SOFTWARE\ABB\Products\SYS_600",
                        "SOFTWARE\Wow6432Node\ABB\Products\SYS_600");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ABB\Products\SYS_600")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\ABB\Products\SYS_600")){
    exit(0);
  }
}

foreach key (key_list)
{
  mcver = registry_get_sz(item:"MajorRelease", key:key);
  mcpath = registry_get_sz(item:"Path", key:key);
  if(!mcpath){
    mcpath = "Unable to get install location from registry";
  }

  if(mcver)
  {
    set_kb_item(name:"MicroSCADA/Win/Installed", value:TRUE);
    set_kb_item(name:"MicroSCADA/Win/Ver", value:mcver);

    cpe = build_cpe(value:mcver, exp:"^([0-9.]+)", base:"cpe:/a:abb:microscada:");
    if(isnull(cpe))
      cpe = "cpe:/a:abb:microscada";

    register_product(cpe: cpe, location: mcpath);
    log_message(data: build_detection_report(app: "ABB MicroSCADA",
                                               version: mcver,
                                               install: mcpath,
                                                   cpe: cpe,
                                             concluded: mcver));
    exit(0);
  }
}
exit(0);

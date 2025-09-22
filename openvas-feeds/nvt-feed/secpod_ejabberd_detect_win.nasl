# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902529");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ejabberd Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"This script finds the installed ejabberd version.

The script logs in via smb, searches for ejabberd in the registry and gets the
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
  key_list = make_list("SOFTWARE\ProcessOne\ejabberd");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\ProcessOne\ejabberd");
}

if(isnull(key_list)){
    exit(0);
}

key = "SOFTWARE\ProcessOne\ejabberd";
key1 = "SOFTWARE\Wow6432Node\ProcessOne\ejabberd";

if(!registry_key_exists(key:key))
{
  if(!registry_key_exists(key:key1))
  {
    exit(0);
  }
}

foreach key (key_list)
{
  ejVer = registry_get_sz(key:key, item:"Version");

  if(ejVer)
  {
    ejPath = registry_get_sz(key:key, item:"Location");
    if(!ejPath){
      ejPath = "Could not find the install location from registry";
    }

    set_kb_item(name:"ejabberd/Win/Ver", value:ejVer);

    cpe = build_cpe(value:ejVer, exp:"^([0-9.]+)", base:"cpe:/a:process-one:ejabberd:");
    if(isnull(cpe))
      cpe = "cpe:/a:process-one:ejabberd";

    register_product(cpe:cpe, location:ejPath);
    log_message(data: build_detection_report(app: "ejabberd",
                                             version:ejVer,
                                             install: ejPath ,
                                             cpe:cpe,
                                             concluded:ejVer));
  }
}

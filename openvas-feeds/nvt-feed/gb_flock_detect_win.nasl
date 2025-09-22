# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800877");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Flock Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"qod_type", value:"executable_version");

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects the installed version of Flock Browser.");

  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Flock Version Detection (Windows)";

if(!get_kb_item("SMB/WindowsVersion"))
{
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Flock\Flock"))
{
  foreach item (registry_enum_keys(key:"SOFTWARE\Flock\Flock"))
  {
    flockVer = eregmatch(pattern:"([0-9]\.[0-9.]+((b|rc)[0-9])?)", string:item);

    if(!isnull(flockVer[1])){
      version = flockVer[1];
    }
  }
}

if(version == NULL)
{
  path = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\flock.exe";
  flockPath = registry_get_sz(key:path, item:"Path");
  if(!isnull(flockPath))
  {
    flockPath = flockPath + "\flock.exe";
    version = GetVersionFromFile(file:flockPath, verstr:"prod");
  }
}

if(version != NULL){
  set_kb_item(name:"Flock/Win/Ver", value:version);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:flock:flock:");
  if(isnull(cpe))
    cpe = "cpe:/a:flock:flock";

  register_product(cpe: cpe, location: flockPath, port:0, service:"smb-login");
  log_message(data: build_detection_report(app: "Flock",
                                         version: version,
                                         install: flockPath,
                                             cpe: cpe,
                                       concluded: version));
  exit(0);
}

exit(0);

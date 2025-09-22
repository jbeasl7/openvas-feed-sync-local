# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836135");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-15 11:15:42 +0530 (Tue, 15 Apr 2025)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Update Setup (Chromium-based) Detection (Windows SMB Login)");
  script_tag(name:"summary", value:"This script detects the installed version
  of Microsoft Edge Update Setup (Chromium-based) for Windows.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch) {
key = "SOFTWARE\Microsoft\EdgeUpdate";
}
else if("x64" >< osArch) {
key = "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate";
}

if(registry_key_exists(key:key)) {
  appName = "Microsoft Edge Update Setup (Chromium-based)";
  version = registry_get_sz(key:key, item:"version");
  path = registry_get_sz(key:key, item:"path");
  if(!path) {
    path = "Could not find the installed location";
  }
  if(version) {
    set_kb_item(name:"Mseus/Win/Ver", value:version);
    set_kb_item(name:"Mseus/Win/detected", value:TRUE);

    #Manually Constructed CPE
    register_and_report_cpe( app:appName, ver:version, concluded:version,
                             base:"cpe:/a:microsoft:edge_update_setup:", expr:"^([0-9.]+)",
                             insloc:path, regService:"smb-login", regPort:0 );
    exit(0);
  }
}

exit(0);

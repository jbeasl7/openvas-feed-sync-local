# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131456");
  script_version("2026-05-22T06:54:41+0000");
  script_tag(name:"last_modification", value:"2026-05-22 06:54:41 +0000 (Fri, 22 May 2026)");
  script_tag(name:"creation_date", value:"2026-04-16 13:10:12 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Microsoft Windows Server Domain Role Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB-login based domain role detection with powershell fallback
  for Windows Server.");

  exit(0);
}

include("smb_nt.inc");
include("powershell_func.inc");

if(get_kb_item("SMB/WindowsVersion")){

  key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
  item = "ProductType";
  type = "HKLM";

  if(! system_type = registry_get_sz( key:key, item:item, type:type)){
    #Standalone Workstation (0) Member Workstation (1) Standalone Server (2) Member Server (3) Backup Domain Controller (4) Primary Domain Controller (5)
    system_type_cmd = "(Get-CimInstance Win32_ComputerSystem).DomainRole";
    system_type = powershell_cmd(cmd:system_type_cmd);
  }

  if(system_type == "5" || system_type == "4" || system_type == "LanmanNT"){
    system_type = "DomainController";
  } else if (system_type == "3" || system_type == "2" || system_type == "ServerNT"){
    system_type = "MemberServer";
  } else {
    exit(0);
  }

  #Microsoft/Windows/MemberServer or Microsoft/Windows/DomainController
  set_kb_item(name:"Microsoft/Windows/" + system_type, value:TRUE);
  exit(0);
}

exit(0);




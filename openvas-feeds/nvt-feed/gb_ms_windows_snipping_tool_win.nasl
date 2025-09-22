# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836384");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-05-29 12:19:02 +0530 (Thu, 29 May 2025)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Snipping Tool (Windows SMB Login)");
  script_tag(name:"summary", value:"SMB login-based detection of Microsoft Windows Snipping Tool");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

appVer = fetch_file_version(sysPath:sysPath, file_name:"System32\SnippingTool.exe");

if(appVer) {
  appPath = sysPath + "\System32";
  set_kb_item(name:"SnippingTool/Win/Installed", value:TRUE);
  set_kb_item(name:"SnippingTool/Win/Ver", value:appVer);

  register_and_report_cpe( app:"Microsoft Windows Snipping Tool", ver:appVer, concluded:appVer[0],
                           base:"cpe:/a:microsoft:snipping_tool:", expr:"^([0-9.]+)",
                           insloc:appPath, regService:"smb-login", regPort:0 );
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2006 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11431");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("XoloX Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 Xue Yong Zhi");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of XoloX.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XoloX", item:"DisplayName");
if(rootfile)
  log_message(port:0);

exit(0);
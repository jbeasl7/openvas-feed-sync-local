# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900019");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3493");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("RealVNC vncviewer.exe Remote DoS Vulnerability - Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30499");

  script_tag(name:"summary", value:"RealVNC is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to lack of adequate boundary check while
  parsing user supplied data.");

  script_tag(name:"affected", value:"RealVNC 4.1.2 and prior on Windows (All).");

  script_tag(name:"solution", value:"Upgrade to RealVNC Version 4.5.3 or later");

  script_tag(name:"impact", value:"Remote attacker can cause application to crash,
  denying the service, and also can execute arbitrary code.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

vncVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinVNC_is1", item:"DisplayVersion");
if(!vncVer){
  vncVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RealVNC_is1", item:"DisplayVersion");
}

if(!vncVer){
  exit(0);
}

if(ereg(pattern:"^([0-3]\..*|4\.(0\..*|1\.[0-2]))$", string:vncVer)){
  security_message(port:0);
}
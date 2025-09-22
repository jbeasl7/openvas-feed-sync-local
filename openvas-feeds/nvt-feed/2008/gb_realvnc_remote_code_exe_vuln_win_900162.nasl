# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900162");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-29 14:53:11 +0100 (Wed, 29 Oct 2008)");
  script_cve_id("CVE-2008-4770");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("RealVNC VNC Viewer Remote Code Execution Vulnerability - Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32317/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31832");
  script_xref(name:"URL", value:"http://www.realvnc.com/products/free/4.1/release-notes.html");

  script_tag(name:"impact", value:"Successful exploitation will allow execution of arbitrary code when user
  connects to a malicious server.");

  script_tag(name:"affected", value:"RealVNC VNC Free Edition version prior to 4.1.3");

  script_tag(name:"solution", value:"Update to version 4.1.3.");

  script_tag(name:"summary", value:"RealVNC VNC Viewer is prone to a security vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in 'CMsgReader::readRect()' function in
  common/rfb/CMsgReader.cxx processing encoding types, and is exploited by
  sending specially crafted messages to the application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RealVNC_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

vncVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!vncVer) exit(0);

if(egrep(pattern:"^(4\.[01](\.[0-2])?)($|[^.0-9])", string:vncVer)){
  report = report_fixed_ver(installed_version:vncVer, fixed_version:"4.1.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
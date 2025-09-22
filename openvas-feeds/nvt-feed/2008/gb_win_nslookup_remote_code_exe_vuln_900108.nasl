# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900108");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3648");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Windows");
  script_name("Microsoft Windows NSlookup.exe RCE Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://securitytracker.com/id?1020711");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/44423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30636");
  script_xref(name:"URL", value:"http://www.nullcode.com.ar/ncs/crash/nsloo.htm");

  script_tag(name:"summary", value:"Windows XP SP2 is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in 'NSlookup.exe' file,
  which could be exploited by attackers.");

  script_tag(name:"affected", value:"Microsoft Windows 2K and XP.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation causes remote code execution, and
  Denial-of-Service.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

winPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!winPath){
  exit(0);
}

winPath += "\nslookup.exe";
port = kb_smb_transport();

winVer = GetVersionFromFile(file:winPath, verstr:"prod", offset:50000);

if(egrep(pattern:"^5\.(0?1\.2600\.([01]?[0-9]?[0-9]?[0-9]|20[0-9][0-9]|21[0-7]" +
                 "[0-9]|2180)|0?0\.2195\.([0-5]?[0-9]?[0-9]?[0-9]|6[0-5][[0-9]" +
                 "[0-9]|66[0-5][0-9]|666[0-3]))$", string:winVer)){
  security_message(port:port);
}

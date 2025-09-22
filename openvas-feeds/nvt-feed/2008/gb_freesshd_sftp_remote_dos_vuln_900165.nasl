# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900165");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_cve_id("CVE-2008-4762");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Denial of Service");
  script_name("freeSSHd SFTP 'rename' and 'realpath' Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://freesshd.com/index.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31872");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6800");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32366/");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service.");

  script_tag(name:"affected", value:"freeSSHd freeSSHd version 1.2.1.14 and prior on Windows (all)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to freeSSHd version 1.2.6 or later.");

  script_tag(name:"summary", value:"freeSSHd SSH server is prone to a remote denial of service vulnerability. NULL pointer de-referencing errors in SFTP 'rename' and 'realpath' commands. These can be exploited by passing overly long string passed as an argument to the affected commands.");

  script_xref(name:"URL", value:"http://www.freesshd.com/index.php?ctt=download");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sshdPath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\FreeSSHDService", item:"ImagePath");
if(!sshdPath){
  exit(0);
}

fileVer = GetVersionFromFile(file:sshdPath);

if(egrep(pattern:"^1\.([01](\..*)|2(\.[01](\.[0-9]|\.1[0-4])?)?)$",
         string:fileVer)){
  security_message(port:0);
}

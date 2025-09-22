# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900411");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Vim Shell Command Injection Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30731/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32462");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-shellescape.html");

  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary shell commands
  to compromise the system.");

  script_tag(name:"affected", value:"Vim version prior to 7.2 on Windows.");

  script_tag(name:"insight", value:"This error is due to the 'filetype.vim', 'tar.vim', 'zip.vim', 'xpm.vim',
  'xpm2.vim', 'gzip.vim', and 'netrw.vim' scripts which are insufficiently filtering escape characters.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to version 7.2.");

  script_tag(name:"summary", value:"Vim is prone to a command injection vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  ver = registry_get_sz(key:key + item, item:"DisplayName");
  if("Vim" >< ver)
  {
    if(egrep(pattern:"Vim ([0-6](\..*)?|7\.[01](\..*)?)", string:ver)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

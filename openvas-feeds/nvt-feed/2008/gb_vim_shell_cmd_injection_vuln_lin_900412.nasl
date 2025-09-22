# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900412");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Vim Shell Command Injection Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30731/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32462");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-shellescape.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary shell commands
  to compromise the system.");

  script_tag(name:"affected", value:"Vim version prior to 7.2 on Linux.");

  script_tag(name:"insight", value:"This error is due to the 'filetype.vim', 'tar.vim', 'zip.vim', 'xpm.vim',
  'xpm2.vim', 'gzip.vim', and 'netrw.vim' scripts which are insufficiently filtering special characters.");

  script_tag(name:"solution", value:"Upgrade to version 7.2 or later.");

  script_tag(name:"summary", value:"Vim is prone to a command injection vulnerability.");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(sock)
{
  vimVer = ssh_cmd(socket:sock, cmd:"vim --version", timeout:120);
  ssh_close_connection();
  if("VIM" >< vimVer){
    pattern = "Vi IMproved ([0-6](\..*)?|7\.[01](\..*)?)";
    if(egrep(pattern:pattern, string:vimVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

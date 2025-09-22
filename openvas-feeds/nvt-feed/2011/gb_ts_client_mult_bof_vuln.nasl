# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902297");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-0900", "CVE-2011-0901");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Terminal Server Client RDP File Processing BOF Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46099");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65100");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16095/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"insight", value:"Multiple flaws are due to a boundary error in the
  'tsc_launch_remote()' function, when processing a 'hostname', 'username',
  'password' and 'domain' parameters.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Terminal Server Client is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
  code, crash the application or deny service to legitimate users.");

  script_tag(name:"affected", value:"Terminal Server Client version 0.150.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/doc/tsclient/NEWS\.gz$", useregex:TRUE, sock:sock);
foreach binName (paths)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  tscVer = ssh_get_bin_version(full_prog_name:"zcat", version_argv:binName, ver_pattern:"v.([0-9]\.[0-9]+)" ,sock:sock);
  if(tscVer[1] != NULL)
  {
    if(version_is_equal(version:tscVer[1], test_version:"0.150"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      close(sock);
      exit(0);
    }
  }
}

close(sock);
ssh_close_connection();

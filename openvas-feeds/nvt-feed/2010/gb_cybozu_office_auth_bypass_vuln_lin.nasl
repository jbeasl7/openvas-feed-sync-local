# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902065");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2029");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Cybozu Office Authentication Bypass Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39508");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/57976");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN87730223/index.html");
  script_xref(name:"URL", value:"http://www.ipa.go.jp/security/english/vuln/201004_cybozu_en.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"insight", value:"The flaw exists due to insufficient checks being performed when accessing
  the 'login' interface.");

  script_tag(name:"solution", value:"Cybozu Office 8 (8.1.0.1).");

  script_tag(name:"summary", value:"Cybozu Office is prone to an authentication bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass authentication
  and obtain or modify sensitive information by using the unique ID of the 'user&qts' cell phone.");

  script_tag(name:"affected", value:"Cybozu Office version before 8 (8.1.0.1).");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

cbofName = ssh_find_file(file_name:"/sched$", useregex:TRUE, sock:sock);

foreach binaryName (cbofName)
{
  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  cbofVer = ssh_get_bin_version(full_prog_name:binaryName, sock:sock, version_argv:"--version", ver_pattern:"Cybozu_Scheduling_Service ([0-9.]+)");

  if(cbofVer[1] != NULL)
  {
    if(version_is_less(version:cbofVer[1], test_version:"8.1.0.1")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
close(sock);
ssh_close_connection();

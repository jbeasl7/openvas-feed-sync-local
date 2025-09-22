# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800068");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5027", "CVE-2008-5028");
  script_name("Nagios <= 3.0.5 CSRF / Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32543");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32156");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32610");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute certain commands
  with disable notification actions when a logged-in user visits a malicious web site.");

  script_tag(name:"affected", value:"Nagios 3.0.5 and prior on Linux.");

  script_tag(name:"insight", value:"The flaw exists due to improper validation of user supplied inputs passed
  to custom form, browser addon and cmd.cgi script.");

  script_tag(name:"summary", value:"Nagios is prone to cross-site request forgery (CSRF) and
  authentication bypass vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Nagios version 3.2.1 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

getPath = ssh_find_file(file_name:"/nagios$", useregex:TRUE, sock:sock);
if(!getPath){
  ssh_close_connection();
  exit(0);
}

foreach binaryFile(getPath) {

  binaryFile = chomp(binaryFile);
  if(!binaryFile) continue;

  nsVer = ssh_get_bin_version(full_prog_name:binaryFile, version_argv:"-V", ver_pattern:"Nagios ([0-9.]+)", sock:sock);
  if(nsVer[1]){
    if(version_is_less_equal(version:nsVer[1], test_version:"3.0.5")){
      report = report_fixed_ver(installed_version:nsVer[1], fixed_version:"3.2.1", install_path:binaryFile);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

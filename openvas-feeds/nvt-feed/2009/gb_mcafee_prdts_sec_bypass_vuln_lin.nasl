# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900359");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1348");
  script_name("McAfee Products Security Bypass Vulnerability (SB10001) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34780");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/case-for-av-bypassesevasions.html");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/mcafee-multiple-bypassesevasions-ziprar.html");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10001&actp=LIST_RECENT");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass the anti-virus
  scanning and distribute files containing malicious code that the antivirus
  application will fail to detect.");

  script_tag(name:"affected", value:"McAfee VirusScan Command Line

  McAfee VirusScan Enterprise Linux

  McAfee software that uses DAT files prior to 5600 on Linux.");

  script_tag(name:"insight", value:"Error in AV Engine fails to handle specially crafted packets via,

  - an invalid Headflags and Packsize fields in a malformed RAR archive.

  - an invalid Filelength field in a malformed ZIP archive.");

  script_tag(name:"solution", value:"Updates are available through DAT files 5600 or later.");

  script_tag(name:"summary", value:"McAfee products are prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

datPath = ssh_find_bin(prog_name:"uvscan_secure", sock:sock);
if(!datPath){
  ssh_close_connection();
  exit(0);
}

foreach path(datPath) {

  path = chomp(path);
  if(!path) continue;

  ver = ssh_cmd(cmd:path + " --version", socket:sock, timeout:60);

  datVer = eregmatch(pattern:"Virus data file v([0-9]{4})", string:strstr(ver, "Virus data file v"));
  if(datVer[1]){
    if(version_is_less(version:datVer[1], test_version:"5600")){
      report = report_fixed_ver(installed_version:datVer[1], fixed_version:"5600", install_path:path);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

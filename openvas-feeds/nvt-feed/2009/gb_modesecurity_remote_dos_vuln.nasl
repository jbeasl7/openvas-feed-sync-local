# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800626");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1902", "CVE-2009-1903");
  script_name("ModSecurity Multiple Remote Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34256");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34096");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8241");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0703");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause denial of
  service.");

  script_tag(name:"affected", value:"ModSecurity version prior to 2.5.9 on Linux.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the PDF XSS protection implementation which can be exploited
    to cause a crash via a specially crafted HTTP request.

  - NULL pointer dereference error when parsing multipart requests can be
    exploited to cause a crash via multipart content with a missing part header
    name.");

  script_tag(name:"solution", value:"Upgrade to version 2.5.9 or later.");

  script_tag(name:"summary", value:"ModSecurity is prone to Denial of Service Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("ModSecurity v[0-9]\\+.[0-9]\\+.[0-9]\\+");

modName = ssh_find_file(file_name:"/mod_security2\.so$", useregex:TRUE, sock:sock);
foreach binaryName (modName) {

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  modsecVer = ssh_get_bin_version(full_prog_name:"grep", version_argv:arg, ver_pattern:"([0-9]+\.[0-9]+\.[0-9]+)", sock:sock);
  if(modsecVer[1]){
    if(version_is_less(version:modsecVer[1], test_version:"2.5.9")){
      report = report_fixed_ver(installed_version:modsecVer[1], fixed_version:"2.5.9", install_path:binaryName);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

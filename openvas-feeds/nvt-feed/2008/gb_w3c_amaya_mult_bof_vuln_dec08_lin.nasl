# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800313");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-09 13:27:23 +0100 (Tue, 09 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5282");
  script_name("W3C Amaya Multiple Buffer Overflow Vulnerabilities (Dec 2008) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32442");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisories/amaya-id.txt");
  script_xref(name:"URL", value:"http://www.bmgsec.com.au/advisories/amaya-url.txt");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/3255");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary code or
  crash an affected browser.");

  script_tag(name:"affected", value:"W3C Amaya Web Browser Version 10.0.1 and prior on Linux.");

  script_tag(name:"insight", value:"The flaws are due to boundary error when processing,

  - HTML <div> tag with a long id field.

  - link with a long HREF attribute.");

  script_tag(name:"solution", value:"Update to a later version. Please see the references for more info.");

  script_tag(name:"summary", value:"W3C Amaya Web Browser is prone to multiple stack based Buffer Overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

amayaPath = ssh_find_file(file_name:"/AmayaPage_WX\.html$", useregex:TRUE, sock:sock);
if(!amayaPath){
  ssh_close_connection();
  exit(0);
}

foreach path(amayaPath){

  path = chomp(path);
  if(!path) continue;

  arg = path + " | grep -i amaya";
  amayaVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:arg, ver_pattern:"Amaya ([.0-9]+)", sock:sock);
  if(amayaVer[1]){
    if(version_is_less_equal(version:amayaVer[1], test_version:"10.0.1")){
      report = report_fixed_ver(installed_version:amayaVer[1], fixed_version:"See references", install_path:path);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

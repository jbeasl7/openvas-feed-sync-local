# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801915");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-1652");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("pWhois Layer Four Traceroute (LFT) Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/946652");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain privileges.");

  script_tag(name:"affected", value:"pWhois Layer Four Traceroute (LFT) 3.x before 3.3.");

  script_tag(name:"insight", value:"An unspecified vulnerability exists in application, which allows local users
  to gain privileges via a crafted command line.");

  script_tag(name:"solution", value:"Upgrade Layer Four Traceroute to 3.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Whois Layer Four Traceroute (LFT) is prone to an unspecified vulnerability.");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_bin(prog_name:"lft", sock:sock);
foreach bin(paths) {

  bin = chomp(bin);
  if(!bin)
    continue;

  lftVer = ssh_get_bin_version(full_prog_name:bin, sock:sock, version_argv:"-v", ver_pattern:"version ([0-9.]+)");

  if(!isnull(lftVer[1])) {
    if(version_in_range(version:lftVer[1], test_version:"3.0", test_version2:"3.2")) {
      report = report_fixed_ver(installed_version:lftVer[1], fixed_version:"3.3");
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

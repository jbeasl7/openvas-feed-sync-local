# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801428");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2795", "CVE-2010-2796");
  script_name("phpCAS Session Hijacking and Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42162");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60894");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60895");
  script_xref(name:"URL", value:"https://issues.jasig.org/browse/PHPCAS-61");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"insight", value:"The flaw exists due to:

  - improper validation of service tickets prior to assigning the new session.
    This can be exploited to hijack another user's session by guessing valid
    service tickets.

  - improper validation of the callback URL.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to phpCAS version 1.1.2 or later.");

  script_tag(name:"summary", value:"phpCAS is prone to session hijacking and cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site and to hijack another user's account and gain the victims privileges.");

  script_tag(name:"affected", value:"phpCAS version prior to 1.1.2.");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = ssh_find_file(file_name:"/CAS\.php$", useregex:TRUE, sock:sock);

foreach binName(paths) {

  binName = chomp(binName);
  if(!binName)
    continue;

  casVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:"PHPCAS_VERSION'.? '([0-9.]+)", sock:sock);

  if(!isnull(casVer[1])) {
    if(version_is_less(version:casVer[1], test_version:"1.1.2")) {
      report = report_fixed_ver(installed_version:casVer[1], fixed_version:"1.1.2");
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);

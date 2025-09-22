# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802259");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-0182");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple Mac OS X 'i386_set_ldt()' Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46997");
  script_xref(name:"URL", value:"http://support.apple.com/kb/DL1367");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00006.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  with elevated privileges.");

  script_tag(name:"affected", value:"Mac OS X version 10.6 through 10.6.6

  Mac OS X Server version 10.6 through 10.6.6.");

  script_tag(name:"insight", value:"The flaw is due to a privilege checking issue exists in the
  i386_set_ldt system call, while handling call gates. This allows local users to gain privileges via vectors
  involving the creation of a call gate entry.");

  script_tag(name:"solution", value:"Upgrade to Mac OS X / Mac OS X Server version 10.6.7 or later.");

  script_tag(name:"summary", value:"Mac OS X is prone to a privilege escalation vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(osVer =~ "^10\.6\." && version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.6.7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
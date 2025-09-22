# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102052");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-3969");
  script_name("Panda Antivirus Buffer Overflow");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/474247/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24989");
  script_xref(name:"URL", value:"http://secunia.com/advisories/26171");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Buffer overflow");
  script_dependencies("panda_av_update_detect.nasl");
  script_mandatory_keys("Panda/AntiVirus/LastUpdate");

  script_tag(name:"solution", value:"The vulnerability was reported on May 07 2007
  and an update has been issued on July 20 2007 to solve this vulnerability through the regular update mechanism.");

  script_tag(name:"summary", value:"Buffer overflow in Panda Antivirus before 20-07-2007
  allows remote attackers to execute arbitrary code via a crafted EXE file, resulting from an Integer Cast Around.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vuln_update = "20-07-2007";
#software not updated after this date is vulnerable

if (!last_update = get_kb_item("Panda/AntiVirus/LastUpdate")) exit(0);

#This part of code converts the dates in a format that
#is checkable using the version_func.inc constructs
last_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$", replace:"\3.\2.\1", string:last_update);
vuln_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$", replace:"\3.\2.\1",  string:vuln_update);

if(version_is_less(version: last_update, test_version:vuln_update)){
  report = report_fixed_ver(installed_version:last_update, fixed_version:vuln_update);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

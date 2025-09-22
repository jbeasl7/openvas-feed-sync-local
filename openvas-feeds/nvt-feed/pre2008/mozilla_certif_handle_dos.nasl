# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Marcel Boesch <marboesc@student.ethz.ch>.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14668");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10703");
  script_cve_id("CVE-2004-0758");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mozilla/Firefox security manager certificate handling DoS");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"solution", value:"Upgrade to the latest version of this software");
  script_tag(name:"summary", value:"The remote host is using Mozilla, an alternative web browser.

  The Mozilla Personal Security Manager (PSM) contains  a flaw
  that may permit an attacker to import silently a certificate into
  the PSM certificate store.
  This corruption may result in a deny of SSL connections.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(!mozVer){
  exit(0);
}

if(version_in_range(version:mozVer, test_version:"1.5", test_version2:"1.7")){
  report = report_fixed_ver(installed_version:mozVer, vulnerable_range:"1.5 - 1.7");
  security_message(port: 0, data: report);
}



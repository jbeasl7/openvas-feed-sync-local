# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  Ref: Max <spamhole@gmx.at>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15432");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11166");
  script_cve_id("CVE-2004-0906");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mozilla/Firefox default installation file permission flaw");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"solution", value:"Update to the latest version of the software");
  script_tag(name:"summary", value:"The remote host is using Mozilla and/or Firefox, an alternative web browser.
  The remote version of this software is prone to an improper file permission
  setting.

  This flaw only exists if the browser is installed by the Mozilla Foundation
  package management, thus this alert might be a false positive.

  A local attacker could overwrite arbitrary files or execute arbitrary code in
  the context of the user running the browser.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(mozVer)
{
  if(version_is_less(version:mozVer ,test_version:"1.7.3"))
  {
    report = report_fixed_ver(installed_version:mozVer, fixed_version:"1.7.3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tunBirdVer = get_kb_item("Thunderbird/Win/Ver");
if(!tunBirdVer){
  exit(0);
}

if(version_is_less(version:tunBirdVer,test_version:"0.8")){
  report = report_fixed_ver(installed_version:tunBirdVer, fixed_version:"0.8");
  security_message(port: 0, data: report);
}

exit(99);

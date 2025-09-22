# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14181");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0763", "CVE-2004-0764");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla/Firefox user interface spoofing");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"solution", value:"None at this time");
  script_tag(name:"summary", value:"The remote host is using Mozilla and/or Firefox, an alternative web browser.
  This web browser supports the XUL (XML User Interface Language), a language
  designed to manipulate the user interface of the browser itself.

  Since XUL gives the full control of the browser GUI to the visited websites,
  an attacker may use it to spoof a third party website and therefore pretend
  that the URL and Certificates of the website are legitimate.

  In addition to this, the remote version of this browser is vulnerable to a
  flaw which may allow a malicious web site to spoof security properties
  such as SSL certificates and URIs.");
  script_xref(name:"URL", value:"http://www.nd.edu/~jsmith30/xul/test/spoof.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10832");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(mozVer)
{
  if(version_is_less(version:mozVer ,test_version:"1.7"))
  {
    report = report_fixed_ver(installed_version:mozVer, fixed_version:"1.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tunBirdVer = get_kb_item("Thunderbird/Win/Ver");
if(!tunBirdVer){
  exit(0);
}

if(version_is_less(version:tunBirdVer ,test_version:"0.7")){
  report = report_fixed_ver(installed_version:tunBirdVer, fixed_version:"0.7");
  security_message(port: 0, data: report);
}

exit(99);

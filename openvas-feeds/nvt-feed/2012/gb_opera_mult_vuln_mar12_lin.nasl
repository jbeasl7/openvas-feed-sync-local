# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802828");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-1924", "CVE-2012-1925", "CVE-2012-1926", "CVE-2012-1927",
                "CVE-2012-1928", "CVE-2012-1930", "CVE-2012-1931");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-29 19:43:23 +0530 (Thu, 29 Mar 2012)");
  script_name("Opera Multiple Vulnerabilities (Mar 2012) - Linux");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1010/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1011/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1012/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1013/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1014/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1015/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1162/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the browser, inject scripts, bypass certain security
  restrictions, conduct spoofing attacks or cause a denial of service
  condition.");
  script_tag(name:"affected", value:"Opera version prior to 11.62 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - An error in web page dialogs handling which displays the wrong address in
    the address field.

  - An error in 'history.state' which leaks the state data from cross domain
    pages via 'history.pushState' and 'history.replaceState' functions.

  - It fails to ensure that a dialog window is placed on top of content
    windows, allows attackers to trick users into executing downloads.

  - A small window for the download dialog.

  - A timed page reloads and redirects to different domains.

  - printing issues which allows data leaks to other system users or
    allows them to corrupt data.");
  script_tag(name:"solution", value:"Upgrade to the Opera version 11.62 or later.");
  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.62")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.62");
  security_message(port:0, data:report);
}

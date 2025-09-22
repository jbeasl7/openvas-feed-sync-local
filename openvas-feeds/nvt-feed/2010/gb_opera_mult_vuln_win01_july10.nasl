# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801369");
  script_version("2024-02-22T14:37:29+0000");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2657", "CVE-2010-2658", "CVE-2010-2662", "CVE-2010-2663",
                "CVE-2010-2664");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser < 10.60 Multiple Vulnerabilities (Jul 2010) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40375");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/957/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1664");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1060/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  execute arbitrary code.");
  script_tag(name:"affected", value:"Opera version prior to 10.60 and prior on Windows.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Browser does not properly prevent certain double-click operations from running
    a program located on a web site.

  - Browser does not properly restrict certain interaction between plug-ins, file
    inputs, and the clipboard, which allows attackers to trigger the uploading of
    arbitrary files via a crafted web site.

  - Error in the handling of popup blocker via a 'javascript:' URL and a
    'ake click'.

  - Error in the handling of an ended event handler that changes the SRC attribute
    of an AUDIO element.

  - Error in the handling of certain HTML content that has an unclosed 'SPAN' element
    with absolute positioning.");
  script_tag(name:"solution", value:"Upgrade to Opera 10.60 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Opera web browser is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"10.60")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.60");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

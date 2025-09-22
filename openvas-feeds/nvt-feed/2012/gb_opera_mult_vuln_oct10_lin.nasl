# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802731");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2010-4043", "CVE-2010-4044", "CVE-2010-4046", "CVE-2010-4045",
                "CVE-2010-4047", "CVE-2010-4049", "CVE-2010-4048", "CVE-2010-4050");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-05 14:23:48 +0530 (Thu, 05 Apr 2012)");
  script_name("Opera Browser Multiple Vulnerabilities (Oct 2010) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41740");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/971/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1063/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Oct/1024570.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  on the target user's system, can obtain sensitive information.");
  script_tag(name:"affected", value:"Opera Web Browser version prior 10.63 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are cause due to:

  - Failure to prevent interpretation of a 'cross-origin' document as a 'CSS'
    stylesheet when the document lacks a CSS token sequence.

  - An error when altering the size of the browser window may cause the wrong
    part of the URL of a web page to be displayed.

  - An error in the handling of reloads and redirects combined with caching may
    result in scripts executing in the wrong security context.

  - Failure to properly verify the origin of video content, which allows remote
    attackers to obtain sensitive information by using a video stream as HTML5
    canvas content.

  - Failure to properly restrict web script in unspecified circumstances involving
    reloads and redirects.

  - Failure to properly select the security context of JavaScript code associated
    with an error page.

  - Error in 'SVG' document in an 'IMG' element.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser version 10.63 or later.");
  script_tag(name:"summary", value:"Opera browser is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");

if(operaVer)
{
  if(version_is_less(version:operaVer, test_version:"10.63")){
    report = report_fixed_ver(installed_version:operaVer, fixed_version:"10.63");
    security_message(port:0, data:report);
  }
}

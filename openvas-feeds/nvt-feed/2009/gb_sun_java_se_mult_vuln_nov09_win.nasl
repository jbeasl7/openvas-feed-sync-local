# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900978");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3728", "CVE-2009-3729", "CVE-2009-3864", "CVE-2009-3879",
                "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883",
                "CVE-2009-3884", "CVE-2009-3885");
  script_name("Sun Java SE Multiple Vulnerabilities (Nov 2009) - Windows");
  script_xref(name:"URL", value:"http://java.sun.com/javase/6/webnotes/6u17.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36881");
  script_xref(name:"URL", value:"http://java.sun.com/j2se/1.5.0/ReleaseNotes.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  script_tag(name:"impact", value:"Successful exploitation allows remote attacker to execute arbitrary code,
  gain escalated privileges, bypass security restrictions and cause denial
  of service attacks inside the context of the affected system.");

  script_tag(name:"affected", value:"Sun Java SE 6 prior to 6 Update 17

  Sun Java SE 5 prior to 5 Update 22 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws occur due to:

  - Directory traversal vulnerability in 'ICC_Profile.getInstance' method.

  - Unspecified error in TrueType font parsing functionality.

  - When a non-English version of Windows is used, the Java Update functionality
    does not retrieve available new JRE versions.

  - Failure to clone arrays that are returned by the 'getConfigurations()'
    function in X11 and Win32GraphicsDevice.

  - The Abstract Window Toolkit (AWT) does not properly restrict the objects
    that may be sent to loggers.

  - Information leak occurs as the application does not prevent the existence
    of children of a resurrected ClassLoader.

  - Multiple unspecified errors in the Swing implementation.

  - The 'TimeZone.getTimeZone' method allows users to probe for the existence
    of local files via vectors related to handling of zoneinfo.

  - Error during parsing of BMP files containing UNC ICC links.");

  script_tag(name:"solution", value:"Upgrade to JRE version 6 Update 17 or later.

  OR

  Upgrade to JRE version 5 Update 22.");

  script_tag(name:"summary", value:"Sun Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ver = get_kb_item("Sun/Java/JRE/Win/Ver");
if(!ver)
  ver = get_kb_item("Sun/Java/JDK/Win/Ver");

if(!ver || ver !~ "^1\.[56]\.")
  exit(0);

if(version_in_range(version:ver, test_version:"1.5", test_version2:"1.5.0.21")||
   version_in_range(version:ver, test_version:"1.6", test_version2:"1.6.0.16")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

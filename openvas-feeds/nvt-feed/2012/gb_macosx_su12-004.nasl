# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802968");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0650",
                "CVE-2012-1173", "CVE-2012-3719", "CVE-2012-0831", "CVE-2012-1172",
                "CVE-2012-1823", "CVE-2012-2143", "CVE-2012-2311", "CVE-2012-2386",
                "CVE-2012-2688", "CVE-2012-0671", "CVE-2012-0670", "CVE-2012-3722",
                "CVE-2012-0668", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317",
                "CVE-2011-3026", "CVE-2011-3048", "CVE-2011-4599", "CVE-2011-3389",
                "CVE-2012-1667", "CVE-2012-3718", "CVE-2012-3720");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-09-25 19:33:16 +0530 (Tue, 25 Sep 2012)");
  script_name("Mac OS X v10.6.8 Multiple Vulnerabilities (2012-004)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47545");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49957");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50494");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51705");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52891");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55612");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55623");
  script_xref(name:"URL", value:"http://support.apple.com/kb/DL1586");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50628/");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.8");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a buffer overflow,
  disclose potentially sensitive information or cause a DoS.");
  script_tag(name:"affected", value:"Apache
  BIND
  CoreText
  Data Security
  DirectoryService
  ImageIO
  Installer
  International Components for Unicode
  Kernel
  LoginWindow
  Mail
  Mobile Accounts
  PHP
  Profile Manager
  QuickLook
  QuickTime
  Ruby
  USB");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Run Mac Updates and update the Security Update 2012-004.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2012-004.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("pkg-lib-macosx.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.004")){
      report = report_fixed_ver(installed_version:osVer, vulnerable_range:"Equal to 10.6.8");
      security_message(port:0, data:report);
    }
  }
}

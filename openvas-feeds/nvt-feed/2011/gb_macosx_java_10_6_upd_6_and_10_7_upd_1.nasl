# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902630");
  script_tag(name:"creation_date", value:"2011-11-17 11:36:14 +0100 (Thu, 17 Nov 2011)");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_version("2025-07-25T05:44:05+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545",
                "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549",
                "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554",
                "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560",
                "CVE-2011-3561");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:29:45 +0000 (Wed, 24 Jul 2024)");
  script_name("Java for Mac OS X 10.6 Update 6 And 10.7 Update 1");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50231");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50250");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4884");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4885");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/Security-announce//2011/Nov/msg00000.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.(6\.8|7\.2)");
  script_tag(name:"impact", value:"Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.");
  script_tag(name:"affected", value:"Java for Mac OS X v10.6.6 and v10.7.2 or Mac OS X Server v10.6.8 and v10.7.2.");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the below links.");
  script_tag(name:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 6 and 10.7 Update 1.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 6 and 10.7 Update 1.");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6", diff:"6"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if(version_is_equal(version:osVer, test_version:"10.7.2"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.7", diff:"1")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902557");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450",
                "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465",
                "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470",
                "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4476");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Java for Mac OS X 10.6 Update 4");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4562");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46404");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46406");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46409");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/mar/msg00001.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.6");
  script_tag(name:"impact", value:"Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.");
  script_tag(name:"affected", value:"Java for Mac OS X v10.6.6 and Mac OS X Server v10.6.6");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the below links.");
  script_tag(name:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 4.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 4.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

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
  if(version_is_equal(version:osVer, test_version:"10.6.6"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6Update", diff:"4"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

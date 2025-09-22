# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902553");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0862", "CVE-2011-0863",
                "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868",
                "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0873");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Java for Mac OS X 10.5 Update 10");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48138");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48140");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48145");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48149");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce//2011//Jun/msg00002.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.5]\.8");
  script_tag(name:"impact", value:"Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user.");
  script_tag(name:"affected", value:"Java for Mac OS X v10.5.8 and Mac OS X Server v10.5.8");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the below links.");
  script_tag(name:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 10.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.5 Update 10.");
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
  if(version_is_equal(version:osVer, test_version:"10.5.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.5Update", diff:"10"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

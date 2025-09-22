# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802794");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2011-3389", "CVE-2012-0651", "CVE-2011-0241", "CVE-2011-2692",
                "CVE-2011-1167", "CVE-2011-1777", "CVE-2011-1778", "CVE-2012-0654",
                "CVE-2012-0655", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834",
                "CVE-2011-3919", "CVE-2012-0657", "CVE-2012-0658", "CVE-2012-0659",
                "CVE-2012-0660", "CVE-2011-1004", "CVE-2011-1005", "CVE-2011-4815",
                "CVE-2012-0870", "CVE-2012-1182", "CVE-2012-0662", "CVE-2012-0652",
                "CVE-2012-0649", "CVE-2012-0036", "CVE-2012-0642", "CVE-2011-3212",
                "CVE-2012-0656", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0830",
                "CVE-2012-0661", "CVE-2012-0675", "CVE-2011-2895", "CVE-2011-3328");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 15:53:00 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-05-18 12:26:01 +0530 (Fri, 18 May 2012)");
  script_name("Mac OS X Multiple Vulnerabilities (2012-002)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46458");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46460");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49124");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49279");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50109");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51300");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51665");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52364");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53457");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53458");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53459");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53462");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53468");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53470");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53473");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5281");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00001.html");
  script_xref(name:"URL", value:"http://prod.lists.apple.com/archives/security-announce/2012/May/msg00001.html");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[67]\.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context or cause a denial of service condition.");
  script_tag(name:"affected", value:"Login Window,
  Bluetooth,
  curl,
  Directory Service,
  HFS,
  ImageIO,
  Kernel,
  libarchive,
  libsecurity,
  libxml,
  LoginUIFramework,
  PHP,
  Quartz Composer,
  QuickTime,
  Ruby,
  Samba,
  Security Framework,
  Time Machine,
  X11.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mac OS X 10.7.4 or
  Run Mac Updates and update the Security Update 2012-002");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2012-002.");
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
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  if(version_is_equal(version:osVer, test_version:"10.6.8"))
  {
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.002"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  if(version_in_range(version:osVer, test_version:"10.7", test_version2:"10.7.3")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

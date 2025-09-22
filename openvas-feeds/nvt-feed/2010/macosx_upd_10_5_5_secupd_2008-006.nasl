# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102033");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2008-2305", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-0314", "CVE-2008-1833",
                "CVE-2008-1835", "CVE-2008-1836", "CVE-2008-1837", "CVE-2008-2713", "CVE-2008-3215",
                "CVE-2008-2329", "CVE-2008-2330", "CVE-2008-2331", "CVE-2008-3613", "CVE-2008-2327",
                "CVE-2008-2332", "CVE-2008-3608", "CVE-2008-1382", "CVE-2008-3609", "CVE-2008-1447",
                "CVE-2008-3610", "CVE-2008-3611", "CVE-2008-1483", "CVE-2008-1657", "CVE-2008-3614",
                "CVE-2008-2376", "CVE-2008-3616", "CVE-2008-2312", "CVE-2008-3617", "CVE-2008-3618",
                "CVE-2008-3619", "CVE-2008-3621", "CVE-2008-3622");
  script_name("Mac OS X 10.5.5 Update / Security Update 2008-006");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:19:00 +0000 (Tue, 24 Mar 2020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT3137");

  script_tag(name:"summary", value:"The remote host is missing Mac OS X 10.5.5 Update / Security Update 2008-006.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  ATS

 BIND

 ClamAV

 Directory Services

 Finder

 ImageIO

 Kernel

 libresolv

 Login Window

 mDNSResponder

 OpenSSH

 QuickDraw Manager

 Ruby

 SearchKit

 System Configuration

 System Preferences

 Time Machine

 VideoConference

 Wiki Server");

  script_tag(name:"solution", value:"Update your Mac OS X operating system. Please see the references for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver || ssh_osx_ver !~ "^10\.[45]\.") exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.4","Mac OS X Server 10.5.4");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.006"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.006"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.4")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.5")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.4")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.5")) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0); }
}

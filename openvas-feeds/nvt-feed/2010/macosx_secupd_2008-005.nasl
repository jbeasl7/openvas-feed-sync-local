# SPDX-FileCopyrightText: 2010 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102024");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
  script_cve_id("CVE-2008-2830", "CVE-2008-1447", "CVE-2008-2320", "CVE-2008-2321", "CVE-2008-2322",
                "CVE-2008-2323", "CVE-2008-2324", "CVE-2008-2952", "CVE-2007-5135", "CVE-2008-2051",
                "CVE-2008-2050", "CVE-2007-4850", "CVE-2008-0599", "CVE-2008-0674", "CVE-2008-2325",
                "CVE-2007-6199", "CVE-2007-6200");
  script_name("Mac OS X Security Update 2008-005");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 13:52:57 +0000 (Fri, 02 Feb 2024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[45]\.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT2647");

  script_tag(name:"summary", value:"The remote host is missing Security Update 2008-005.");

  script_tag(name:"affected", value:"One or more of the following components are affected:

  Open Scripting Architecture

 BIND

 CarbonCore

 CoreGraphics

 Data Detectors Engine

 Disk Utility

 OpenLDAP

 OpenSSL

 PHP

 QuickLook

 rsync");

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
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.005"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.005"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.4")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.4"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X 10.5.4")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.005"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.4")) {
  if(version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.4"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
  else if((ssh_osx_ver == osx_ver(ver:"Mac OS X Server 10.5.4")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.005"))) { security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);}
}

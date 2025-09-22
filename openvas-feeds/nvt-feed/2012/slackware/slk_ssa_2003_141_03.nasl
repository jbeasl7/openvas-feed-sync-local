# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53900");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-141-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-141-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.424088");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SSA:2003-141-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in the xdrmem_getbytes() function found in the glibc
library has been fixed. This could allow a remote attacker to execute
arbitrary code by exploiting RPC service that use xdrmem_getbytes(). None of
the default RPC services provided by Slackware appear to use this function,
but third-party applications may make use of it.

We recommend upgrading to these new glibc packages.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Tue May 20 20:13:09 PDT 2003
patches/packages/glibc-2.3.1-i386-4.tgz: Patched, recompiled.
 (* Security fix *)
patches/packages/glibc-debug-2.3.1-i386-4.tgz: Patched, recompiled.
 (* Security fix *)
patches/packages/glibc-i18n-2.3.1-noarch-4.tgz: Rebuilt.
patches/packages/glibc-profile-2.3.1-i386-4.tgz: Patched, recompiled.
 (* Security fix *)
patches/packages/glibc-solibs-2.3.1-i386-4.tgz: Patched a buffer overflow in
 some dead code (xdrmem_getbytes(), which we couldn't find used by anything,
 but it doesn't hurt to patch it anyway)
 (* Security fix *)
patches/packages/glibc-zoneinfo-2.3.1-noarch-4.tgz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'glibc' package(s) on Slackware 8.1, Slackware 9.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.2.5-i386-4", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.2.5-i386-4", rls:"SLK8.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.3.1-i386-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-debug", ver:"2.3.1-i386-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.3.1-noarch-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.3.1-i386-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.3.1-i386-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.3.1-noarch-4", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1844.1");
  script_cve_id("CVE-2014-8121", "CVE-2015-1781");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1844-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1844-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151844-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945779");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001651.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2015:1844-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"glibc was updated to fix bugs and security issues.

Security issues fixed:

* A buffer overflow in nss_dns was fixed that could lead to crashes. (CVE-2015-1781, bsc#927080, BZ #18287)
* A denial of service attack (out of memory) in the NSS files backend was fixed (CVE-2014-8121, bsc#918187, GLIBC BZ #18007)

Non security bugs fixed:

* Fix regression in threaded application malloc performance (bsc#915955, GLIBC#17195)
* Fix read past end of pattern in fnmatch (bsc#920338, GLIBC#17062, GLIBC#18032, GLIBC#18036)
* Record TTL also for DNS PTR queries (bsc#928723, GLIBC#18513)
* Increase MINSIGSTKSZ and SIGSTKSZ for aarch64 (bsc#931480, GLIBC#16850)
* Fix handling of IPv6 nameservers (bsc#939211, GLIBC#13028, GLIBC#17053)
* Avoid use of asm/ptrace.h (bsc#934084)
* Do not corrupt the top of a threaded heap if top chunk is MINSIZE (GLIBC#18502)
* Terminate unwinding after makecontext_ret on s390 (bsc#940332. bsc#944494, GLIBC#18508)
* Restore signal mask in set/swapcontext on s390 (bsc#940195, bsc#944494, GLIBC#18080)
* fix dlopen in static binaries (bsc#937853, GLIBC#17250)
* Properly reread entry after failure in nss_files getent function (bsc#945779, BZ #18991)

Features added:

* AVX512 support (fate#318844)
* Add compatibility symlinks for LSB 3.0 (fate#318933)");

  script_tag(name:"affected", value:"'glibc' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.19~22.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.19~22.7.1", rls:"SLES12.0"))) {
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

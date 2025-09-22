# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0471.1");
  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-21 14:12:44 +0000 (Thu, 21 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0471-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0471-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160471-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962739");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-February/001883.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2016:0471-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glibc fixes the following security issues:

- CVE-2015-7547: A stack-based buffer overflow in getaddrinfo allowed remote attackers to cause a crash or execute arbitrary code via crafted and timed DNS responses (bsc#961721)
- CVE-2015-8777: Insufficient checking of LD_POINTER_GUARD environment variable allowed local attackers to bypass the pointer guarding protection of the dynamic loader on set-user-ID and set-group-ID programs (bsc#950944)
- CVE-2015-8776: Out-of-range time values passed to the strftime function may cause it to crash, leading to a denial of service, or potentially disclosure information (bsc#962736)
- CVE-2015-8778: Integer overflow in hcreate and hcreate_r could have caused an out-of-bound memory access. leading to application crashes or, potentially, arbitrary code execution (bsc#962737)
- CVE-2014-9761: A stack overflow (unbounded alloca) could have caused applications which process long strings with the nan function to crash or, potentially, execute arbitrary code. (bsc#962738)
- CVE-2015-8779: A stack overflow (unbounded alloca) in the catopen function could have caused applications which pass long strings to the catopen function to crash or, potentially execute arbitrary code. (bsc#962739)

The following non-security bugs were fixed:

- bsc#955647: Resource leak in resolver
- bsc#956716: Don't do lock elision on an error checking mutex
- bsc#958315: Reinitialize dl_load_write_lock on fork");

  script_tag(name:"affected", value:"'glibc' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.19~35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.19~35.1", rls:"SLES12.0SP1"))) {
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

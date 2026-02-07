# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0371.1");
  script_cve_id("CVE-2025-15281", "CVE-2026-0861", "CVE-2026-0915");
  script_tag(name:"creation_date", value:"2026-02-06 04:35:55 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0371-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260371-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257005");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2026:0371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-0861: Fixed inadequate size check in the memalign suite may result in an integer overflow (bsc#1256766).
- CVE-2026-0915: Fixed uninitialized stack buffer used as DNS query name when net==0 in _nss_dns_getnetbyaddr_r (bsc#1256822).
- CVE-2025-15281: Fixed uninitialized memory may cause the process abort (bsc#1257005).

Other fixes:

- NPTL: Optimize trylock for high cache contention workloads (bsc#1256437).");

  script_tag(name:"affected", value:"'glibc' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static", rpm:"glibc-devel-static~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-static-32bit", rpm:"glibc-devel-static-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-extra", rpm:"glibc-extra~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-lang", rpm:"glibc-lang~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base", rpm:"glibc-locale-base~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-base-32bit", rpm:"glibc-locale-base-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils-32bit", rpm:"glibc-utils-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnsl1", rpm:"libnsl1~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnsl1-32bit", rpm:"libnsl1-32bit~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.38~150600.14.40.1", rls:"openSUSELeap15.6"))) {
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

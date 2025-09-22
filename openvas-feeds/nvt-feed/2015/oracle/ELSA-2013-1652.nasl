# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123531");
  script_cve_id("CVE-2013-0221", "CVE-2013-0222", "CVE-2013-0223");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1652)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1652");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1652.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils' package(s) announced via the ELSA-2013-1652 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[8.4-31.0.1]
- clean up empty file if cp is failed [Orabug 15973168]

[8.4-31]
- adjust the fix for the du bindmounts failure(#836557)

* Mon Oct 07 2013 Ondrej Oprala - Fix su retvals (once again)
 [8.4-29]
- CVE-2013-0221 CVE-2013-0223 CVE-2013-0222 - fix various
 segmentation faults in sort, uniq and join(#1015019)
 [8.4-28]
- su now returns correct retvals for all cases
 [8.4-27]
- tail -F now disables inotify when encountering a symlink.
 Polling is used instead.
 * Mon Sep 16 2013 Ondrej Oprala - df now properly dereferences long FS names(again)
 [8.4-25]
- pr -n no longer crashes when passed values >= 32.
 Also line numbers are consistently padded with spaces,
 rather than with zeros for certain widths. (#997537)
 [8.4-24]
- fix su return codes when NOT killed by a signal (#996190)
 [8.4-23]
- fix several newly introduced defects found by Coverity
 check
 [8.4-22]
- wait for su child to prevent erroneous execution of some
 commands (#749679)
- correct return values after signal termination (#889531)
 and propagation of child core dump info (#747592)
- dd now accepts 'status=none' to suppress all
 informational output(#965654)
- cut --output-delimiter option was ignored for multibyte
 locales (#867984)
- remove redundant setpwent() and setgrent () syscalls
 from stat -U/-G to improve NIS performance (#911206)
- date: deal correctly with invalid input with special
 characters (#960160)
- dd: provide support for the conv=sparse (#908980)
- su/runuser: clarify which envvars are preserved/initialized
 in -p/-m and -l help/man documentation (#967623)
- du: properly detect bindmounts (#836557)
- df: fix alignment of columns (#842040)
- id,groups: fix correct group printing (#816708)
- mv : replace empty directories in cross file
 system move (#980061)
 [8.4-21]
- fix parsing of field regression in sort command
 (introduced between RHEL5 and RHEL6 upstream) (#956143)
 [8.4-20]
- revert to polling for unknown filesystems, update
 known fs for tail and stat based on coreutils-8.21 (#827199)");

  script_tag(name:"affected", value:"'coreutils' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~8.4~31.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreutils-libs", rpm:"coreutils-libs~8.4~31.0.1.el6", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123882");
  script_cve_id("CVE-2012-0833");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0813)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0813");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0813.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2012-0813 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.10.2-15]
- Resolves: Bug 824014 - DS Shuts down intermittently

[1.2.10.2-14]
- Resolves: Bug 819643 - Database RUV could mismatch the one in changelog under the stress
-- patch 0015 fixes a small memleak in previous patch

[1.2.10.2-13]
- Resolves: Bug 822700 - Bad DNs in ACIs can segfault ns-slapd

[1.2.10.2-12]
- Resolves: Bug 819643 - Database RUV could mismatch the one in changelog under the stress
- Resolves: Bug 821542 - letters in object's cn get converted to lowercase when renaming object

[1.2.10.2-11]
- Resolves: Bug 819643 - Database RUV could mismatch the one in changelog under the stress
- 1.2.10.2-10 was built from the private branch

[1.2.10.2-10]
- Resolves: Bug 819643 - Database RUV could mismatch the one in changelog under the stress

[1.2.10.2-9]
- Resolves: Bug 815991 - crash in ldap_initialize with multiple threads
- previous fix was still crashing in ldclt

[1.2.10.2-8]
- Resolves: Bug 815991 - crash in ldap_initialize with multiple threads

[1.2.10.2-7]
- Resolves: Bug 813964 - IPA dirsvr seg-fault during system longevity test

[1.2.10.2-6]
- Resolves: Bug 811291 - [abrt] 389-ds-base-1.2.10.4-2.fc16: index_range_read_ext: Process /usr/sbin/ns-slapd was killed by signal 11 (SIGSEGV)
- typo in previous patch

[1.2.10.2-5]
- Resolves: Bug 811291 - [abrt] 389-ds-base-1.2.10.4-2.fc16: index_range_read_ext: Process /usr/sbin/ns-slapd was killed by signal 11 (SIGSEGV)

[1.2.10.2-4]
- Resolves: Bug 803930 - ipa not starting after upgrade because of missing data
- get rid of posttrans - move update code to post

[1.2.10.2-3]
- Resolves: Bug 800215 - Certain CMP operations hang or cause ns-slapd to crash

[1.2.10.2-2]
- Resolves: Bug 800215 - Certain CMP operations hang or cause ns-slapd to crash
- Resolves: Bug 800217 - fix valgrind reported issues

[1.2.10.2-1]
- Resolves: Bug 766989 - Rebase 389-ds-base to 1.2.10
- Resolves: Bug 796770 - crash when replicating orphaned tombstone entry

[1.2.10.1-1]
- Resolves: Bug 766989 - Rebase 389-ds-base to 1.2.10
- Resolves: Bug 790491 - 389 DS Segfaults during replica install in FreeIPA

[1.2.10.0-1]
- Resolves: Bug 766989 - Rebase 389-ds-base to 1.2.10

[1.2.10-0.11.rc2]
- Resolves: Bug 766989 - Rebase 389-ds-base to 1.2.10

[1.2.9.16-1]
- Bug 759301 - Incorrect entryUSN index under high load in replicated environment
- Bug 743979 - Add slapi_rwlock API and use POSIX rwlocks
- WARNING - patches 0030 and 0031 remove and add back the file configure
- this is necessary because the merge commit to rebase RHEL-6 to 1.2.9.6
- seriously messed up configure - so in order to add the patch for 743979
- which also touched configure, the file had to be removed and added back
- also note that the commit for the RHEL-6 branch to remove configure does
- not work - the way patch works, it has to match every line exactly in
- order to remove the file, and because the merge commit messed things
- up, it doesn't work
- So, DO ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.10.2~15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.10.2~15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.10.2~15.el6", rls:"OracleLinux6"))) {
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

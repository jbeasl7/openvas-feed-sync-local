# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3790.1");
  script_cve_id("CVE-2019-12625", "CVE-2019-12900", "CVE-2019-15961", "CVE-2019-1785", "CVE-2019-1786", "CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789", "CVE-2019-1798", "CVE-2020-3123", "CVE-2020-3327", "CVE-2020-3341", "CVE-2020-3350", "CVE-2020-3481");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-21 15:39:26 +0000 (Fri, 21 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3790-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3790-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203790-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2020:3790-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

clamav was updated to the new major release 0.103.0.
(jsc#ECO-3010,bsc#1118459)

Note that libclamav was changed incompatible, if you have a 3rd party application that uses libclamav, it needs to be rebuilt.

Update to 0.103.0

clamd can now reload the signature database without blocking scanning.
 This multi-threaded database reload improvement was made possible thanks
 to a community effort.

 - Non-blocking database reloads are now the default behavior. Some
 systems that are more constrained on RAM may need to disable
 non-blocking reloads as it will temporarily consume two times as much
 memory. We added a new clamd config option ConcurrentDatabaseReload,
 which may be set to no.

 * Fix clamav-milter.service (requires clamd.service to run)

Update to 0.102.4

 * CVE-2020-3350: Fix a vulnerability wherein a malicious user could
 replace a scan target's directory with a symlink to another path to
 trick clamscan, clamdscan, or clamonacc into removing or moving a
 different file (eg. a critical system file). The issue would affect
 users that use the --move or --remove options for clamscan, clamdscan,
 and clamonacc.
 * CVE-2020-3327: Fix a vulnerability in the ARJ archive parsing module
 in ClamAV 0.102.3 that could cause a Denial-of-Service (DoS)
 condition. Improper bounds checking results in an
 out-of-bounds read which could cause a crash. The previous fix for
 this CVE in 0.102.3 was incomplete. This fix correctly resolves the
 issue.
 * CVE-2020-3481: Fix a vulnerability in the EGG archive module in ClamAV
 0.102.0 - 0.102.3 could cause a Denial-of-Service (DoS) condition.
 Improper error handling may result in a crash due to a NULL pointer
 dereference. This vulnerability is mitigated for those using the
 official ClamAV signature databases because the file type signatures
 in daily.cvd will not enable the EGG archive parser in versions
 affected by the vulnerability.

Update to 0.102.3

 * CVE-2020-3327: Fix a vulnerability in the ARJ archive parsing module
 in ClamAV 0.102.2 that could cause a Denial-of-Service (DoS)
 condition. Improper bounds checking of an unsigned variable results in
 an out-of-bounds read which causes a crash.
 * CVE-2020-3341: Fix a vulnerability in the PDF parsing module in ClamAV
 0.101 - 0.102.2 that could cause a Denial-of-Service (DoS) condition.
 Improper size checking of a buffer used to initialize AES decryption
 routines results in an out-of-bounds read which may cause a crash.
 * Fix 'Attempt to allocate 0 bytes' error when parsing some PDF
 documents.
 * Fix a couple of minor memory leaks.
 * Updated libclamunrar to UnRAR 5.9.2.

Update to 0.102.2:

 * CVE-2020-3123: A denial-of-service (DoS) condition may occur when
 using the optional credit card data-loss-prevention (DLP) feature.
 Improper bounds checking of an unsigned variable resulted in an
 out-of-bounds read, which ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.0~3.23.1", rls:"SLES15.0SP2"))) {
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

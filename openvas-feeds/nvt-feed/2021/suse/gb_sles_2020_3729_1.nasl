# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3729.1");
  script_cve_id("CVE-2019-12625", "CVE-2019-12900", "CVE-2019-15961", "CVE-2020-3123", "CVE-2020-3327", "CVE-2020-3341", "CVE-2020-3350", "CVE-2020-3481");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-21 15:39:26 +0000 (Fri, 21 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3729-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3729-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203729-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174255");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/007946.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2020:3729-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

clamav was updated to 0.103.0 to implement jsc#ECO-3010 and bsc#1118459.

* clamd can now reload the signature database without blocking
 scanning. This multi-threaded database reload improvement was made
 possible thanks to a community effort.
 - Non-blocking database reloads are now the default behavior. Some
 systems that are more constrained on RAM may need to disable
 non-blocking reloads as it will temporarily consume two times as
 much memory. We added a new clamd config option
 ConcurrentDatabaseReload, which may be set to no.
* Fix clamav-milter.service (requires clamd.service to run)
* Fix freshclam crash in FIPS mode. (bsc#1119353)

Update to version 0.102.4:

Accumulated security fixes:

* CVE-2020-3350: Fix a vulnerability wherein a malicious user could
 replace a scan target's directory with a symlink to another path
 to trick clamscan, clamdscan, or clamonacc into removing or moving
 a different file (eg. a critical system file). The issue would
 affect users that use the --move or --remove options for clamscan,
 clamdscan, and clamonacc. (bsc#1174255)
* CVE-2020-3327: Fix a vulnerability in the ARJ archive parsing
 module in ClamAV 0.102.3 that could cause a Denial-of-Service
 (DoS) condition. Improper bounds checking results in an
 out-of-bounds read which could cause a crash. The previous fix for
 this CVE in 0.102.3 was incomplete. This fix correctly resolves
 the issue.
* CVE-2020-3481: Fix a vulnerability in the EGG archive module in
 ClamAV 0.102.0 - 0.102.3 could cause a Denial-of-Service (DoS)
 condition. Improper error handling may result in a crash due to a
 NULL pointer dereference. This vulnerability is mitigated for
 those using the official ClamAV signature databases because the
 file type signatures in daily.cvd will not enable the EGG archive
 parser in versions affected by the vulnerability. (bsc#1174250)
* CVE-2020-3341: Fix a vulnerability in the PDF parsing module in
 ClamAV 0.101 - 0.102.2 that could cause a Denial-of-Service (DoS)
 condition. Improper size checking of a buffer used to initialize AES
 decryption routines results in an out-of-bounds read which may cause
 a crash. (bsc#1171981)
* CVE-2020-3123: A denial-of-service (DoS) condition may occur when
 using the optional credit card data-loss-prevention (DLP) feature.
 Improper bounds checking of an unsigned variable resulted in an
 out-of-bounds read, which causes a crash.
* CVE-2019-15961: A Denial-of-Service (DoS) vulnerability may
 occur when scanning a specially crafted email file as a result
 of excessively long scan times. The issue is resolved by
 implementing several maximums in parsing MIME messages and by
 optimizing use of memory allocation. (bsc#1157763).
* CVE-2019-12900: An out of bounds write in the NSIS bzip2
 (bsc#1149458)
* CVE-2019-12625: Introduce a configurable time limit to mitigate
 zip bomb ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.0~3.3.1", rls:"SLES12.0SP5"))) {
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

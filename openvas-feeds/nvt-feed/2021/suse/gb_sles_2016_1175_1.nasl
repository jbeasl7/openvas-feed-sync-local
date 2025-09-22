# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1175.1");
  script_cve_id("CVE-2015-5300", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-30 21:59:00 +0000 (Mon, 30 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1175-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1175-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161175-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/782060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/784760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975981");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-April/002032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1175-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p6 to fix 12 security issues.

These security issues were fixed:
- CVE-2015-8158: Fixed potential infinite loop in ntpq (bsc#962966).
- CVE-2015-8138: Zero Origin Timestamp Bypass (bsc#963002).
- CVE-2015-7979: Off-path Denial of Service (DoS) attack on authenticated broadcast mode (bsc#962784).
- CVE-2015-7978: Stack exhaustion in recursive traversal of restriction list (bsc#963000).
- CVE-2015-7977: reslist NULL pointer dereference (bsc#962970).
- CVE-2015-7976: ntpq saveconfig command allows dangerous characters in filenames (bsc#962802).
- CVE-2015-7975: nextvar() missing length check (bsc#962988).
- CVE-2015-7974: Skeleton Key: Missing key check allows impersonation between authenticated peers (bsc#962960).
- CVE-2015-7973: Replay attack on authenticated broadcast mode (bsc#962995).
- CVE-2015-8140: ntpq vulnerable to replay attacks (bsc#962994).
- CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose origin (bsc#962997).
- CVE-2015-5300: MITM attacker could have forced ntpd to make a step larger than the panic threshold (bsc#951629).

These non-security issues were fixed:
- fate#320758 bsc#975981: Enable compile-time support for MS-SNTP
 (--enable-ntp-signd). This replaces the w32 patches in 4.2.4 that added
 the authreg directive.
- bsc#962318: Call /usr/sbin/sntp with full path to synchronize in start-ntpd.
 When run as cron job, /usr/sbin/ is not in the path, which caused
 the synchronization to fail.
- bsc#782060: Speedup ntpq.
- bsc#916617: Add /var/db/ntp-kod.
- bsc#956773: Add ntp-ENOBUFS.patch to limit a warning that might happen quite a lot on loaded systems.
- bsc#951559,bsc#975496: Fix the TZ offset output of sntp during DST.
- Add ntp-fork.patch and build with threads disabled to allow name resolution even when running chrooted.
- bsc#784760: Remove local clock from default configuration");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p6~8.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p6~8.2", rls:"SLES11.0SP4"))) {
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

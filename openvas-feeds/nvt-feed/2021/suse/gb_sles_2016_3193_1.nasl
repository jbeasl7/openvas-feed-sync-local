# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3193.1");
  script_cve_id("CVE-2015-5219", "CVE-2015-8139", "CVE-2015-8140", "CVE-2016-7426", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-7429", "CVE-2016-7431", "CVE-2016-7433", "CVE-2016-7434", "CVE-2016-9310", "CVE-2016-9311");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 18:20:25 +0000 (Thu, 18 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3193-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3193-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163193-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992606");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002496.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:3193-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntp fixes the following issues:

- Simplify ntpd's search for its own executable to prevent AppArmor
 warnings (bsc#956365).

Security issues fixed (update to 4.2.8p9):

- CVE-2016-9311, CVE-2016-9310, bsc#1011377: Mode 6
 unauthenticated trap information disclosure and DDoS vector.
- CVE-2016-7427, bsc#1011390:
 Broadcast Mode Replay Prevention DoS.
- CVE-2016-7428, bsc#1011417:
 Broadcast Mode Poll Interval Enforcement DoS.
- CVE-2016-7431, bsc#1011395:
 Regression: 010-origin: Zero Origin Timestamp Bypass.
- CVE-2016-7434, bsc#1011398:
 Null pointer dereference in _IO_str_init_static_internal().
- CVE-2016-7429, bsc#1011404: Interface selection attack.
- CVE-2016-7426, bsc#1011406:
 Client rate limiting and server responses.
- CVE-2016-7433, bsc#1011411: Reboot sync calculation problem.
- CVE-2015-5219: An endless loop due to incorrect precision to
 double conversion (bsc#943216).
- CVE-2015-8140: ntpq vulnerable to replay attacks.
- CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose origin.
- CVE-2015-5219: An endless loop due to incorrect precision to
 double conversion (bsc#943216).

Non-security issues fixed:

- Fix a spurious error message.
- Other bugfixes, see /usr/share/doc/packages/ntp/ChangeLog.
- Fix a regression in 'trap' (bsc#981252).
- Reduce the number of netlink groups to listen on for changes to
 the local network setup (bsc#992606).
- Fix segfault in 'sntp -a' (bsc#1009434).
- Silence an OpenSSL version warning (bsc#992038).
- Make the resolver task change user and group IDs to the same
 values as the main task. (bsc#988028)");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p9~57.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p9~57.2", rls:"SLES11.0SP4"))) {
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

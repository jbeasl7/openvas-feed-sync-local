# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1047.1");
  script_cve_id("CVE-2016-9042", "CVE-2017-6451", "CVE-2017-6458", "CVE-2017-6460", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-29 18:24:37 +0000 (Wed, 29 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1047-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171047-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030050");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002811.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2017:1047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This ntp update to version 4.2.8p10 fixes several issues.

This updated enables leap smearing. See
/usr/share/doc/packages/ntp/README.leapsmear for details.

Security issues fixed (bsc#1030050):

- CVE-2017-6464: Denial of Service via Malformed Config
- CVE-2017-6462: Buffer Overflow in DPTS Clock
- CVE-2017-6463: Authenticated DoS via Malicious Config Option
- CVE-2017-6458: Potential Overflows in ctl_put() functions
- CVE-2017-6451: Improper use of snprintf() in mx4200_send()
- CVE-2017-6460: Buffer Overflow in ntpq when fetching reslist
- CVE-2016-9042: 0rigin (zero origin) DoS.
- ntpq_stripquotes() returns incorrect Value
- ereallocarray()/eallocarray() underused
- Copious amounts of Unused Code
- Off-by-one in Oncore GPS Receiver
- Makefile does not enforce Security Flags

Bugfixes:

- Remove spurious log messages (bsc#1014172).
- clang scan-build findings
- Support for openssl-1.1.0 without compatibility modes
- Bugfix 3072 breaks multicastclient
- forking async worker: interrupted pipe I/O
- (...) time_pps_create: Exec format error
- Incorrect Logic for Peer Event Limiting
- Change the process name of forked DNS worker
- Trap Configuration Fail
- Nothing happens if minsane < maxclock < minclock
- allow -4/-6 on restrict line with mask
- out-of-bound pointers in ctl_putsys and decode_bitflags
- Move ntp-kod to /var/lib/ntp, because /var/db is not a standard directory and causes problems for
 transactional updates.");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p10~46.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p10~46.23.1", rls:"SLES12.0"))) {
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

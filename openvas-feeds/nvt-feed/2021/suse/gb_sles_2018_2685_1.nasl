# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2685.1");
  script_cve_id("CVE-2008-1483", "CVE-2016-10012", "CVE-2016-10708", "CVE-2017-15906");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 19:49:38 +0000 (Thu, 05 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2685-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182685-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092582");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004551.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2018:2685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh provides the following fixes:

Security issues fixed:

- CVE-2017-15906: Stricter checking of operations in read-only mode in sftp server (bsc#1065000).
- CVE-2016-10012: Remove pre-auth compression support from the server to prevent possible cryptographic attacks (bsc#1016370).
- CVE-2008-1483: Refine handling of sockets for X11 forwarding to remove reintroduced CVE-2008-1483 (bsc#1069509).
- CVE-2016-10708: Prevent DoS due to crashes caused by out-of-sequence NEWKEYS message (bsc#1076957).

Bug fixes:

- bsc#1017099: Enable case-insensitive hostname matching.
- bsc#1023275: Add a new switch for printing diagnostic messages in sftp client's batch mode.
- bsc#1048367: systemd integration to work around various race conditions.
- bsc#1053972: Remove duplicate KEX method.
- bsc#1092582: Add missing piece of systemd integration.
- Remove the limit on the amount of tasks sshd can run.");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~54.15.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.6p1~54.15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~6.6p1~54.15.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~6.6p1~54.15.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~54.15.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.6p1~54.15.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~6.6p1~54.15.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~6.6p1~54.15.2", rls:"SLES12.0SP1"))) {
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

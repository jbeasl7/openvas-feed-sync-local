# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1563.1");
  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-05 18:25:39 +0000 (Tue, 05 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1563-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1563-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161563-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982068");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002111.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1563-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p8 to fix five security issues.

These security issues were fixed:
- CVE-2016-4953: Bad authentication demobilizes ephemeral associations (bsc#982065).
- CVE-2016-4954: Processing spoofed server packets (bsc#982066).
- CVE-2016-4955: Autokey association reset (bsc#982067).
- CVE-2016-4956: Broadcast interleave (bsc#982068).
- CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

These non-security issues were fixed:
- Keep the parent process alive until the daemon has finished initialisation, to make sure that the PID file exists when the parent returns.
- bsc#979302: Change the process name of the forking DNS worker process to avoid the impression that ntpd is started twice.
- bsc#981422: Don't ignore SIGCHILD because it breaks wait().
- bsc#979981: ntp-wait does not accept fractional seconds, so use 1 instead of 0.2 in ntp-wait.service.
- Separate the creation of ntp.keys and key #1 in it to avoid problems when upgrading installations that have the file, but no key #1, which is needed e.g. by 'rcntp addserver'.");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
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

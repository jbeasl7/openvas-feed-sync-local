# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1386.1");
  script_cve_id("CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 19:09:13 +0000 (Mon, 17 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1386-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161386-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/729190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975865");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002080.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2016:1386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenSSH fixes three security issues.

These security issues were fixed:
- CVE-2016-3115: Sanitise input for xauth(1) (bsc#970632)
- CVE-2016-1908: Prevent X11 SECURITY circumvention when forwarding X11 connections (bsc#962313)
- CVE-2015-8325: Ignore PAM environment when using login (bsc#975865)

These non-security issues were fixed:
- Fix help output of sftp (bsc#945493)
- Restarting openssh with openssh-fips installed was not working correctly (bsc#945484)
- Fix crashes when /proc is not available in the chroot (bsc#947458)
- Correctly parse GSSAPI KEX algorithms (bsc#961368)
- More verbose FIPS mode/CC related documentation in README.FIPS (bsc#965576, bsc#960414)
- Fix PRNG re-seeding (bsc#960414, bsc#729190)
- Disable DH parameters under 2048 bits by default and allow lowering the limit back to the RFC 4419 specified minimum through an option (bsc#932483, bsc#948902)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.6p1~42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~6.6p1~42.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~6.6p1~42.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6p1~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.6p1~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~6.6p1~42.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~6.6p1~42.1", rls:"SLES12.0SP1"))) {
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

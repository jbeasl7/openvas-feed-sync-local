# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1898.1");
  script_cve_id("CVE-2017-9445");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-05 15:43:24 +0000 (Wed, 05 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1898-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171898-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986216");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003039.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dracut, systemd' package(s) announced via the SUSE-SU-2017:1898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd and dracut fixes the following issues:

Security issues fixed:

- CVE-2017-9445: Possible out-of-bounds write triggered by a specially crafted TCP payload
 from a DNS server. (bsc#1045290)

Non-security issues fixed in systemd:

- Automounter issue in combination with NFS volumes (bsc#1040968)
- Missing symbolic link for SAS device in /dev/disk/by-path (bsc#1040153)
- Add minimal support for boot.d/* scripts in systemd-sysv-convert (bsc#1046750)

Non-security issues fixed in dracut:

- Bail out if module directory does not exist. (bsc#1043900)
- Suppress bogus error message. (bsc#1032029)
- Fix module force loading with systemd. (bsc#986216)
- Ship udev files required by systemd. (bsc#1040153)
- Ignore module resolution errors (e.g. with kgraft). (bsc#1037120)");

  script_tag(name:"affected", value:"'dracut, systemd' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dracut", rpm:"dracut~044.1~109.8.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dracut-fips", rpm:"dracut-fips~044.1~109.8.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~150.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~150.7.1", rls:"SLES12.0SP2"))) {
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

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0158");
  script_cve_id("CVE-2013-0219");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0158)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0158");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0158.html");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098434.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=9027");
  script_xref(name:"URL", value:"https://fedorahosted.org/sssd/ticket/1782");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the MGASA-2013-0158 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A TOCTOU (time-of-check time-of-use) race condition was found in the way SSSD,
System Security Services Daemon, performed copying and removal of (user)
directory trees.A local attacker, with permissions to write into directory of
the victim, being actively / currently copied / removed via the sssd daemon
facility, could use this flaw to conduct symbolic link attacks, leading to
their ability to alter / remove directories outside of originally intended, to
be modified, directory tree (CVE-2013-0219).");

  script_tag(name:"affected", value:"'sssd' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_sudo-devel", rpm:"libsss_sudo-devel~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-lib64ipa_hbac", rpm:"sssd-lib64ipa_hbac~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-lib64ipa_hbac0", rpm:"sssd-lib64ipa_hbac0~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libipa_hbac", rpm:"sssd-libipa_hbac~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libipa_hbac0", rpm:"sssd-libipa_hbac0~1.8.6~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.8.6~1.mga2", rls:"MAGEIA2"))) {
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

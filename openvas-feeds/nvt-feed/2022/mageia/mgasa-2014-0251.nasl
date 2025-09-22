# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0251");
  script_cve_id("CVE-2014-3215");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0251");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0251.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00084.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13459");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcap-ng' package(s) announced via the MGASA-2014-0251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libcap-ng packages fix security vulnerability:

capng_lock() in libcap-ng before 0.7.4 sets securebits in an attempt to
prevent regaining capabilities using setuid-root programs. This allows a
user to run setuid programs, such as seunshare from policycoreutils, as
uid 0 but without capabilities, which is potentially dangerous
(CVE-2014-3215).");

  script_tag(name:"affected", value:"'libcap-ng' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64cap-ng-devel", rpm:"lib64cap-ng-devel~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cap-ng0", rpm:"lib64cap-ng0~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng", rpm:"libcap-ng~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng-devel", rpm:"libcap-ng-devel~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng-utils", rpm:"libcap-ng-utils~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng0", rpm:"libcap-ng0~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libcap-ng", rpm:"python-libcap-ng~0.7.3~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64cap-ng-devel", rpm:"lib64cap-ng-devel~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cap-ng0", rpm:"lib64cap-ng0~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng", rpm:"libcap-ng~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng-devel", rpm:"libcap-ng-devel~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng-utils", rpm:"libcap-ng-utils~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcap-ng0", rpm:"libcap-ng0~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libcap-ng", rpm:"python-libcap-ng~0.7.3~3.1.mga4", rls:"MAGEIA4"))) {
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

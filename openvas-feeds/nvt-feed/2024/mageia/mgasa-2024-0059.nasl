# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0059");
  script_cve_id("CVE-2023-22742", "CVE-2024-24577");
  script_tag(name:"creation_date", value:"2024-03-15 04:12:49 +0000 (Fri, 15 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 14:54:09 +0000 (Thu, 15 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0059)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0059");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0059.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30633");
  script_xref(name:"URL", value:"https://github.com/libgit2/libgit2/security/advisories/GHSA-8643-3wh5-rmjq");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2024/02/msg00012.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014158.html");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3340");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2' package(s) announced via the MGASA-2024-0059 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When using an SSH remote with the optional libssh2 backend, libgit2 does
not perform certificate checking by default. (CVE-2023-22742)
Using well-crafted inputs to `git_index_add` can cause heap corruption
that could be leveraged for arbitrary code execution. (CVE-2024-24577)");

  script_tag(name:"affected", value:"'libgit2' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64git2-devel", rpm:"lib64git2-devel~1.3.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64git2_1.3", rpm:"lib64git2_1.3~1.3.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2", rpm:"libgit2~1.3.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-devel", rpm:"libgit2-devel~1.3.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2_1.3", rpm:"libgit2_1.3~1.3.2~1.1.mga9", rls:"MAGEIA9"))) {
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

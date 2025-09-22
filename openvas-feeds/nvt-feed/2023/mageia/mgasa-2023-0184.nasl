# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0184");
  script_cve_id("CVE-2023-1667", "CVE-2023-2283");
  script_tag(name:"creation_date", value:"2023-05-22 04:13:07 +0000 (Mon, 22 May 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-06 14:54:27 +0000 (Tue, 06 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0184");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0184.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31925");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/C4KR3JZOQP2PX7KTYELHWXLPT3JRJXUM/");
  script_xref(name:"URL", value:"https://www.libssh.org/2023/05/04/libssh-0-10-5-and-libssh-0-9-7-security-releases/");
  script_xref(name:"URL", value:"https://www.libssh.org/security/advisories/CVE-2023-1667.txt");
  script_xref(name:"URL", value:"https://www.libssh.org/security/advisories/CVE-2023-2283.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the MGASA-2023-0184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Potential NULL dereference during rekeying with algorithm guessing.
(CVE-2023-1667)
Authorization bypass in pki_verify_data_signature. (CVE-2023-2283");

  script_tag(name:"affected", value:"'libssh' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh-devel", rpm:"lib64ssh-devel~0.9.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh4", rpm:"lib64ssh4~0.9.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.9.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.7~1.mga8", rls:"MAGEIA8"))) {
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

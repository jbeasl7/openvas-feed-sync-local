# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.179810010059177");
  script_cve_id("CVE-2023-42811");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 14:33:52 +0000 (Tue, 26 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-17bdd59177)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-17bdd59177");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-17bdd59177");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240269");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firecracker, rust-aes-gcm' package(s) announced via the FEDORA-2023-17bdd59177 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the aes-gcm crate to version 0.10.3. Addresses CVE-2023-42811.
- Rebuild dependent packages (firecracker) for aes-gcm v0.10.3.

[link moved to references]");

  script_tag(name:"affected", value:"'firecracker, rust-aes-gcm' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"firecracker", rpm:"firecracker~1.4.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debuginfo", rpm:"firecracker-debuginfo~1.4.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firecracker-debugsource", rpm:"firecracker-debugsource~1.4.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+aes-devel", rpm:"rust-aes-gcm+aes-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+alloc-devel", rpm:"rust-aes-gcm+alloc-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+arrayvec-devel", rpm:"rust-aes-gcm+arrayvec-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+default-devel", rpm:"rust-aes-gcm+default-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+getrandom-devel", rpm:"rust-aes-gcm+getrandom-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+heapless-devel", rpm:"rust-aes-gcm+heapless-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+rand_core-devel", rpm:"rust-aes-gcm+rand_core-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+std-devel", rpm:"rust-aes-gcm+std-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+stream-devel", rpm:"rust-aes-gcm+stream-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm+zeroize-devel", rpm:"rust-aes-gcm+zeroize-devel~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm", rpm:"rust-aes-gcm~0.10.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-aes-gcm-devel", rpm:"rust-aes-gcm-devel~0.10.3~1.fc39", rls:"FC39"))) {
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

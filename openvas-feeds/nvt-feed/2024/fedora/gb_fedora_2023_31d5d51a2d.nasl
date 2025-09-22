# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.31100510051972100");
  script_cve_id("CVE-2023-3832", "CVE-2023-38325");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 03:55:33 +0000 (Thu, 27 Jul 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-31d5d51a2d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-31d5d51a2d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-31d5d51a2d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184207");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184208");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2211237");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231274");
  script_xref(name:"URL", value:"https://cryptography.io/en/latest/changelog/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cryptography, rust-asn1, rust-asn1_derive' package(s) announced via the FEDORA-2023-31d5d51a2d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update python-cryptography to 41.0.3, [link moved to references]
- Security fix for CVE-2023-3832 'SSH certificate encoding/parsing incompatibility with OpenSSH'
- Update rust-asn1 to 0.15.5 and obsolete const-generic feature
- Update rust-asn1_derive to 0.15.5");

  script_tag(name:"affected", value:"'python-cryptography, rust-asn1, rust-asn1_derive' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~41.0.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~41.0.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~41.0.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~41.0.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1+default-devel", rpm:"rust-asn1+default-devel~0.15.5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1+fallible-allocations-devel", rpm:"rust-asn1+fallible-allocations-devel~0.15.5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1+std-devel", rpm:"rust-asn1+std-devel~0.15.5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1", rpm:"rust-asn1~0.15.5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1-devel", rpm:"rust-asn1-devel~0.15.5~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive+default-devel", rpm:"rust-asn1_derive+default-devel~0.15.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive", rpm:"rust-asn1_derive~0.15.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive-devel", rpm:"rust-asn1_derive-devel~0.15.5~1.fc39", rls:"FC39"))) {
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

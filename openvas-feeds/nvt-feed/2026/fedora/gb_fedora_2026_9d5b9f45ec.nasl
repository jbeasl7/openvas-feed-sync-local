# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.910059891024510199");
  script_cve_id("CVE-2026-27459");
  script_tag(name:"creation_date", value:"2026-03-27 04:50:29 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-23 18:05:15 +0000 (Mon, 23 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-9d5b9f45ec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-9d5b9f45ec");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-9d5b9f45ec");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433650");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447727");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448652");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kryoptic, pyOpenSSL, python-cryptography, rust-asn1, rust-asn1_derive, rust-cryptoki, rust-cryptoki-sys, rust-wycheproof' package(s) announced via the FEDORA-2026-9d5b9f45ec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update pyOpenSSL to v26.0.0 (security update)
- Update python-cryptography to v46.0.5 (dependency of pyOpenSSL 26)
- Update rust-asn1 to 0.22 (dependency of python-cryptography)
- Update kryoptic to v1.5 (required for rust-asn1 bump to 0.22)

The security status of this update is _only_ for pyOpenSSL.");

  script_tag(name:"affected", value:"'kryoptic, pyOpenSSL, python-cryptography, rust-asn1, rust-asn1_derive, rust-cryptoki, rust-cryptoki-sys, rust-wycheproof' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"kryoptic", rpm:"kryoptic~1.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kryoptic-debuginfo", rpm:"kryoptic-debuginfo~1.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kryoptic-debugsource", rpm:"kryoptic-debugsource~1.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kryoptic-tools", rpm:"kryoptic-tools~1.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kryoptic-tools-debuginfo", rpm:"kryoptic-tools-debuginfo~1.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyOpenSSL", rpm:"pyOpenSSL~26.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyOpenSSL-doc", rpm:"pyOpenSSL-doc~26.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~46.0.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~46.0.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~46.0.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~46.0.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyOpenSSL", rpm:"python3-pyOpenSSL~26.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1+default-devel", rpm:"rust-asn1+default-devel~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1+std-devel", rpm:"rust-asn1+std-devel~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1", rpm:"rust-asn1~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1-devel", rpm:"rust-asn1-devel~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive+default-devel", rpm:"rust-asn1_derive+default-devel~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive", rpm:"rust-asn1_derive~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asn1_derive-devel", rpm:"rust-asn1_derive-devel~0.22.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki+default-devel", rpm:"rust-cryptoki+default-devel~0.12.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki+generate-bindings-devel", rpm:"rust-cryptoki+generate-bindings-devel~0.12.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki+serde-devel", rpm:"rust-cryptoki+serde-devel~0.12.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki", rpm:"rust-cryptoki~0.12.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-devel", rpm:"rust-cryptoki-devel~0.12.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-sys+bindgen-devel", rpm:"rust-cryptoki-sys+bindgen-devel~0.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-sys+default-devel", rpm:"rust-cryptoki-sys+default-devel~0.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-sys+generate-bindings-devel", rpm:"rust-cryptoki-sys+generate-bindings-devel~0.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-sys", rpm:"rust-cryptoki-sys~0.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cryptoki-sys-devel", rpm:"rust-cryptoki-sys-devel~0.5.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+aead-devel", rpm:"rust-wycheproof+aead-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+cipher-devel", rpm:"rust-wycheproof+cipher-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+default-devel", rpm:"rust-wycheproof+default-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+dsa-devel", rpm:"rust-wycheproof+dsa-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+ec-devel", rpm:"rust-wycheproof+ec-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+ecdh-devel", rpm:"rust-wycheproof+ecdh-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+ecdsa-devel", rpm:"rust-wycheproof+ecdsa-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+eddsa-devel", rpm:"rust-wycheproof+eddsa-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+fpe-devel", rpm:"rust-wycheproof+fpe-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+hkdf-devel", rpm:"rust-wycheproof+hkdf-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+keywrap-devel", rpm:"rust-wycheproof+keywrap-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+mac-devel", rpm:"rust-wycheproof+mac-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+num-bigint-devel", rpm:"rust-wycheproof+num-bigint-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+primality-devel", rpm:"rust-wycheproof+primality-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+rsa_enc-devel", rpm:"rust-wycheproof+rsa_enc-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+rsa_sig-devel", rpm:"rust-wycheproof+rsa_sig-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof+xdh-devel", rpm:"rust-wycheproof+xdh-devel~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof", rpm:"rust-wycheproof~0.6.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wycheproof-devel", rpm:"rust-wycheproof-devel~0.6.0~1.fc43", rls:"FC43"))) {
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

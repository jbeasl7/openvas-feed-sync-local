# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3101522810110123");
  script_cve_id("CVE-2025-24528");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-3e5228ee23)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3e5228ee23");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3e5228ee23");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2214326");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336555");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2341962");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342811");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the FEDORA-2025-3e5228ee23 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Prevent overflow when calculating ulog block size (CVE-2025-24528)
- Support PKCS11 EC client certs in PKINIT
- kdb5_util: fix DB entry flags on modification
- Add ECDH support for PKINIT (RFC5349)");

  script_tag(name:"affected", value:"'krb5' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs-debuginfo", rpm:"krb5-libs-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-debuginfo", rpm:"krb5-pkinit-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-debuginfo", rpm:"krb5-server-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap-debuginfo", rpm:"krb5-server-ldap-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-tests", rpm:"krb5-tests~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation-debuginfo", rpm:"krb5-workstation-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkadm5", rpm:"libkadm5~1.21.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkadm5-debuginfo", rpm:"libkadm5-debuginfo~1.21.3~4.fc41", rls:"FC41"))) {
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

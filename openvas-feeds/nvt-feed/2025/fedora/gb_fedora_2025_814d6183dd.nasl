# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8141006183100100");
  script_cve_id("CVE-2025-32990");
  script_tag(name:"creation_date", value:"2025-07-15 04:17:08 +0000 (Tue, 15 Jul 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:32:53 +0000 (Fri, 15 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-814d6183dd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-814d6183dd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-814d6183dd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2378952");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379272");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the FEDORA-2025-814d6183dd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updates gnutls to the latest upstream release. Notable changes are:

* PKCS#11 cryptographic provider support
* Support for kTLS rekeying with kernel 6.14+
* Support for the almost standardized ML-DSA private key formats

This also fixes 4 CVEs.");

  script_tag(name:"affected", value:"'gnutls' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-c++", rpm:"gnutls-c++~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-c++-debuginfo", rpm:"gnutls-c++-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-dane", rpm:"gnutls-dane~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-dane-debuginfo", rpm:"gnutls-dane-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-fips", rpm:"gnutls-fips~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-utils-debuginfo", rpm:"gnutls-utils-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gnutls", rpm:"mingw32-gnutls~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gnutls-debuginfo", rpm:"mingw32-gnutls-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gnutls", rpm:"mingw64-gnutls~3.8.10~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gnutls-debuginfo", rpm:"mingw64-gnutls-debuginfo~3.8.10~1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.24089872979");
  script_cve_id("CVE-2023-53160", "CVE-2023-53161", "CVE-2025-4574", "CVE-2025-53605");
  script_tag(name:"creation_date", value:"2025-09-26 04:05:15 +0000 (Fri, 26 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 22:15:25 +0000 (Tue, 13 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-2408b72979)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2408b72979");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2408b72979");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366579");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372843");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376753");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384045");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384047");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-az-cvm-vtpm, rust-az-snp-vtpm, rust-az-tdx-vtpm, trustee-guest-components' package(s) announced via the FEDORA-2025-2408b72979 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebase trustee-guest-components to v0.13.0
Include rust-az-???-vtpm packages rebase to version 0.7.4
Adjust (patches) to work with 'sev' version 6.");

  script_tag(name:"affected", value:"'rust-az-cvm-vtpm, rust-az-snp-vtpm, rust-az-tdx-vtpm, trustee-guest-components' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+attester-devel", rpm:"rust-az-cvm-vtpm+attester-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+default-devel", rpm:"rust-az-cvm-vtpm+default-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+openssl-devel", rpm:"rust-az-cvm-vtpm+openssl-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+tpm-devel", rpm:"rust-az-cvm-vtpm+tpm-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+tss-esapi-devel", rpm:"rust-az-cvm-vtpm+tss-esapi-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm+verifier-devel", rpm:"rust-az-cvm-vtpm+verifier-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm", rpm:"rust-az-cvm-vtpm~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-cvm-vtpm-devel", rpm:"rust-az-cvm-vtpm-devel~0.7.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm+attester-devel", rpm:"rust-az-snp-vtpm+attester-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm+default-devel", rpm:"rust-az-snp-vtpm+default-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm+openssl-devel", rpm:"rust-az-snp-vtpm+openssl-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm+verifier-devel", rpm:"rust-az-snp-vtpm+verifier-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm", rpm:"rust-az-snp-vtpm~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-snp-vtpm-devel", rpm:"rust-az-snp-vtpm-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-tdx-vtpm+attester-devel", rpm:"rust-az-tdx-vtpm+attester-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-tdx-vtpm+default-devel", rpm:"rust-az-tdx-vtpm+default-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-tdx-vtpm+verifier-devel", rpm:"rust-az-tdx-vtpm+verifier-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-tdx-vtpm", rpm:"rust-az-tdx-vtpm~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-az-tdx-vtpm-devel", rpm:"rust-az-tdx-vtpm-devel~0.7.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trustee-guest-components", rpm:"trustee-guest-components~0.13.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trustee-guest-components-debuginfo", rpm:"trustee-guest-components-debuginfo~0.13.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trustee-guest-components-debugsource", rpm:"trustee-guest-components-debugsource~0.13.0~3.fc42", rls:"FC42"))) {
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

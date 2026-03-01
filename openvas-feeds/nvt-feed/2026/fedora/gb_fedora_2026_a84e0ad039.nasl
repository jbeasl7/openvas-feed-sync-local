# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9784101097100039");
  script_cve_id("CVE-2025-13465", "CVE-2025-15284", "CVE-2026-23745", "CVE-2026-23950", "CVE-2026-24842");
  script_tag(name:"creation_date", value:"2026-02-16 04:45:23 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-19T05:56:52+0000");
  script_tag(name:"last_modification", value:"2026-02-19 05:56:52 +0000 (Thu, 19 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-18 16:20:07 +0000 (Wed, 18 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-a84e0ad039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-a84e0ad039");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-a84e0ad039");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-sgx' package(s) announced via the FEDORA-2026-a84e0ad039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update nodejs modules used by pccs daemon for CVE-2026-23745, CVE-2026-23950, CVE-2026-24842, CVE-2025-13465, CVE-2025-15284.
Remove Fedora override of default pccs daemon port.
Remove redundant dep on mpa_registration from pccs.
Add system scriptlets for pccs server.
Port to pycryptography & pyasn1.
Fix tracebacks in keyring code.");

  script_tag(name:"affected", value:"'linux-sgx' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx", rpm:"linux-sgx~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx-debuginfo", rpm:"linux-sgx-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-sgx-debugsource", rpm:"linux-sgx-debugsource~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-aesm", rpm:"sgx-aesm~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-aesm-debuginfo", rpm:"sgx-aesm-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-common", rpm:"sgx-common~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-devel", rpm:"sgx-devel~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-devel", rpm:"sgx-enclave-devel~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-devel-debuginfo", rpm:"sgx-enclave-devel-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-ide-unsigned", rpm:"sgx-enclave-latest-ide-unsigned~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-pce-unsigned", rpm:"sgx-enclave-latest-pce-unsigned~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-qe3-unsigned", rpm:"sgx-enclave-latest-qe3-unsigned~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-enclave-latest-tdqe-unsigned", rpm:"sgx-enclave-latest-tdqe-unsigned~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-libs", rpm:"sgx-libs~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-libs-debuginfo", rpm:"sgx-libs-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-mpa", rpm:"sgx-mpa~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-mpa-debuginfo", rpm:"sgx-mpa-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs", rpm:"sgx-pccs~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs-admin", rpm:"sgx-pccs-admin~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pccs-debuginfo", rpm:"sgx-pccs-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pckid-tool", rpm:"sgx-pckid-tool~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sgx-pckid-tool-debuginfo", rpm:"sgx-pckid-tool-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-devel", rpm:"tdx-attest-devel~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-libs", rpm:"tdx-attest-libs~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-attest-libs-debuginfo", rpm:"tdx-attest-libs-debuginfo~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-qgs", rpm:"tdx-qgs~2.26~34.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdx-qgs-debuginfo", rpm:"tdx-qgs-debuginfo~2.26~34.fc43", rls:"FC43"))) {
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

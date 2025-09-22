# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833748");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-25165");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 20:10:18 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:47:25 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for trivy (openSUSE-SU-2023:0064-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0064-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZC5NXZSDG2FYOHGXMQE4LMFVABIGBY3E");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy'
  package(s) announced via the openSUSE-SU-2023:0064-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for trivy fixes the following issues:

     Update to version 0.37.3 (boo#1208091, CVE-2023-25165):

  * chore(helm): update Trivy from v0.36.1 to v0.37.2 (#3574)

  * ci: quote pros in c++ for semantic pr (#3605)

  * fix(image): check proxy settings from env for remote images (#3604)

     Update to version 0.37.2:

  * BREAKING: use normalized trivy-java-db (#3583)

  * fix(image): add timeout for remote images (#3582)

  * fix(misconf): handle dot files better (#3550)

     Update to version 0.37.1:

  * fix(sbom): download the Java DB when generating SBOM (#3539)

  * fix: use cgo free sqlite driver (#3521)

  * ci: fix path to dist folder (#3527)

     Update to version 0.37.0:

  * fix(image): close layers (#3517)

  * refactor: db client changed (#3515)

  * feat(java): use trivy-java-db to get GAV (#3484)

  * docs: add note about the limitation in Rekor (#3494)

  * docs: aggregate targets (#3503)

  * deps: updates wazero to 1.0.0-pre.8 (#3510)

  * docs: add alma 9 and rocky 9 to supported os (#3513)

  * chore: add missing target labels (#3504)

  * docs: add java vulnerability page (#3429)

  * feat(image): add support for Docker CIS Benchmark (#3496)

  * feat(image): secret scanning on container image config (#3495)

  * chore(deps): Upgrade defsec to v0.82.8 (#3488)

  * feat(image): scan misconfigurations in image config (#3437)

  * chore(helm): update Trivy from v0.30.4 to v0.36.1 (#3489)

  * feat(k8s): add node info resource (#3482)

  * perf(secret): optimize secret scanning memory usage (#3453)

  * feat: support aliases in CLI flag, env and config (#3481)

  * fix(k8s): migrate rbac k8s (#3459)

  * feat(java): add implementationVendor and specificationVendor fields to
       detect GroupID from MANIFEST.MF (#3480)

  * refactor: rename security-checks to scanners (#3467)

  * chore: display the troubleshooting URL for the DB denial error (#3474)

  * docs: yaml tabs to spaces, auto create namespace (#3469)

  * docs: adding show-and-tell template to GH discussions (#3391)

  * fix: Fix a temporary file leak in case of error (#3465)

  * fix(test): sort cyclonedx components (#3468)

  * docs: fixing spelling mistakes (#3462)

  * ci: set paths triggering VM tests in PR (#3438)

  * docs: typo in --skip-files (#3454)

  * feat(custom-forward): Extended advisory data (#3444)

  * docs: fix spelling error (#3436)

  * refactor(image): extend image config analyzer (#3434)

  * fix(nodejs): add ignore protocols to yarn parser (#3433)

  * fix(db): check pr ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'trivy' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.37.3~bp154.2.9.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.37.3~bp154.2.9.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
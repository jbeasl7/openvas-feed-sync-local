# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833596");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-1996");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:24:58 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for trivy (openSUSE-SU-2022:10081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10081-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5HVVWQ7QWDT7GBZUAYXIWYZURAWKCEVQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy'
  package(s) announced via the openSUSE-SU-2022:10081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for trivy fixes the following issues:
  trivy was updated to version 0.30.4:

  * fix: remove the first arg when running as a plugin (#2595)

  * fix: k8s controlplaner scanning (#2593)

  * fix(vuln): GitLab report template (#2578)
  Update to version 0.30.3:

  * fix(server): use a new db worker for hot updates (#2581)

  * docs: add trivy with download-db-only flag to Air-Gapped Environment
       (#2583)

  * docs: split commands to download db for different versions of oras
       (#2582)

  * feat(report): export exitcode for license checks (#2564)

  * fix: cli can use lowercase for severities (#2565)

  * fix: allow subcommands with TRIVY_RUN_AS_PLUGIN (#2577)

  * fix: add missing types in TypeOSes and TypeLanguages in analyzer (#2569)

  * fix: enable some features of the wasm runtime (#2575)

  * fix(k8s): no error logged if trivy can't get docker image in kubernetes
       mode (#2521)

  * docs(sbom): improve sbom attestation documentation (#2566)
  Update to version 0.30.2:

  * fix(report): show the summary without results (#2548)

  * fix(cli): replace '-' to '_' for env vars (#2561)
  Update to version 0.30.1:

  * chore: remove a test repository (#2551)

  * fix(license): lazy loading of classifiers (#2547)

  * fix: CVE-2022-1996 in Trivy (#2499)

  * docs(sbom): add sbom attestation (#2527)

  * feat(rocky): set Rocky Linux 9 EOL (#2543)

  * docs: add attributes to the video tag to autoplay demo videos (#2538)

  * fix: yaml files with non-string chart name (#2534)

  * fix: skip dirs (#2530)

  * feat(repo): add support for branch, commit, &amp  tag (#2494)

  * fix: remove auto configure environment variables via viper (#2526)
  Update to version 0.30.0:

  * fix: separating multiple licenses from one line in dpkg copyright files
       (#2508)

  * fix: change a capital letter for `plugin uninstall` subcommand (#2519)

  * fix: k8s hide empty report when scanning resource (#2517)

  * refactor: fix comments (#2516)

  * fix: scan vendor dir (#2515)

  * feat: Add support for license scanning (#2418)

  * chore: add owners for secret scanning (#2485)

  * fix: remove dependency-tree flag for image subcommand (#2492)

  * fix(k8s): add shorthand for k8s namespace flag (#2495)

  * docs: add information about using multiple servers to troubleshooting
       (#2498)

  * ci: add pushing canary build images to registries (#2428)

  * feat(dotnet): add support for .Net core .deps.json files (#2487)

  * feat(amazon): add support for 2022 version (#2429)

  * Type correction bitna ...

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

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.30.4~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.30.4~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
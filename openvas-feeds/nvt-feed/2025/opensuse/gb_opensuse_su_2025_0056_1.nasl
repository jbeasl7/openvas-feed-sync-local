# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0056.1");
  script_cve_id("CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158", "CVE-2024-3817", "CVE-2024-45337", "CVE-2024-45338", "CVE-2025-21613", "CVE-2025-21614");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0056-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DUNHR7ATZWEF5LQKUNEXKL22CUQAND3A/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235265");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy' package(s) announced via the openSUSE-SU-2025:0056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for trivy fixes the following issues:

Update to version 0.58.2 (

 boo#1234512, CVE-2024-45337,
 boo#1235265, CVE-2024-45338):

 * fix(misconf): allow null values only for tf variables [backport: release/v0.58] (#8238)
 * fix(suse): SUSE - update OSType constants and references for compatility [backport: release/v0.58] (#8237)
 * fix: CVE-2025-21613 and CVE-2025-21614 : go-git: argument injection via the URL field [backport: release/v0.58] (#8215)
 * fix(sbom): attach nested packages to Application [backport: release/v0.58] (#8168)
 * fix(python): skip dev group's deps for poetry [backport: release/v0.58] (#8158)
 * fix(sbom): use root package for `unknown` dependencies (if exists) [backport: release/v0.58] (#8156)
 * chore(deps): bump `golang.org/x/net` from `v0.32.0` to `v0.33.0` [backport: release/v0.58] (#8142)
 * chore(deps): bump `github.com/CycloneDX/cyclonedx-go` from `v0.9.1` to `v0.9.2` [backport: release/v0.58] (#8136)
 * fix(redhat): correct rewriting of recommendations for the same vulnerability [backport: release/v0.58] (#8135)
 * fix(oracle): add architectures support for advisories [backport: release/v0.58] (#8125)
 * fix(sbom): fix wrong overwriting of applications obtained from different sbom files but having same app type [backport: release/v0.58] (#8124)
 * chore(deps): bump golang.org/x/crypto from 0.30.0 to 0.31.0 [backport: release/v0.58] (#8122)
 * fix: handle `BLOW_UNKNOWN` error to download DBs [backport: release/v0.58] (#8121)
 * fix(java): correctly overwrite version from depManagement if dependency uses `project.*` props [backport: release/v0.58] (#8119)
 * release: v0.58.0 [main] (#7874)
 * fix(misconf): wrap AWS EnvVar to iac types (#7407)
 * chore(deps): Upgrade trivy-checks (#8018)
 * refactor(misconf): Remove unused options (#7896)
 * docs: add terminology page to explain Trivy concepts (#7996)
 * feat: add `workspaceRelationship` (#7889)
 * refactor(sbom): simplify relationship generation (#7985)
 * docs: improve databases documentation (#7732)
 * refactor: remove support for custom Terraform checks (#7901)
 * docs: drop AWS account scanning (#7997)
 * fix(aws): change CPU and Memory type of ContainerDefinition to a string (#7995)
 * fix(cli): Handle empty ignore files more gracefully (#7962)
 * fix(misconf): load full Terraform module (#7925)
 * fix(misconf): properly resolve local Terraform cache (#7983)
 * refactor(k8s): add v prefix for Go packages (#7839)
 * test: replace Go checks with Rego (#7867)
 * feat(misconf): log causes of HCL file parsing errors (#7634)
 * chore(deps): bump the aws group across 1 directory with 7 updates (#7991)
 * chore(deps): bump github.com/moby/buildkit from 0.17.0 to 0.17.2 in the docker group across 1 directory (#7990)
 * chore(deps): update csaf module dependency from csaf-poc to gocsaf (#7992)
 * chore: downgrade the failed block expand message to debug (#7964)
 * fix(misconf): do not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'trivy' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.58.2~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
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

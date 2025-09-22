# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833048");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-23648", "CVE-2022-28946");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-26 20:00:37 +0000 (Thu, 26 May 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:23:37 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for trivy (openSUSE-SU-2022:10022-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10022-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/43ATI5PP2NX5LEC336CTPYZBZIQPNK2B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy'
  package(s) announced via the openSUSE-SU-2022:10022-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for trivy fixes the following issues:
  trivy was updated to version 0.28.0 (boo#1199760, CVE-2022-28946):

  * fix: remove Highlighted from json output (#2131)

  * fix: remove trivy-kubernetes replace (#2132)

  * docs: Add Operator docs under Kubernetes section (#2111)

  * fix(k8s): security-checks panic (#2127)

  * ci: added k8s scope (#2130)

  * docs: Update misconfig output in examples (#2128)

  * fix(misconf): Fix coloured output in Goland terminal (#2126)

  * docs(secret): Fix default value of --security-checks in docs (#2107)

  * refactor(report): move colorize function from trivy-db (#2122)

  * feat: k8s resource scanning (#2118)

  * chore: add CODEOWNERS (#2121)

  * feat(image): add `--server` option for remote scans (#1871)

  * refactor: k8s (#2116)

  * refactor: export useful APIs (#2108)

  * docs: fix k8s doc (#2114)

  * feat(kubernetes): Add report flag for summary (#2112)

  * fix: Remove problematic advanced rego policies (#2113)

  * feat(misconf): Add special output format for misconfigurations (#2100)

  * feat:  add k8s subcommand (#2065)

  * chore: fix make lint version (#2102)

  * fix(java): handle relative pom modules (#2101)

  * fix(misconf): Add missing links for non-rego misconfig results (#2094)

  * feat(misconf): Added fs.FS based scanning via latest defsec (#2084)

  * chore(deps): bump trivy-issue-action to v0.0.4 (#2091)

  * chore(deps): bump github.com/twitchtv/twirp (#2077)

  * chore(deps): bump github.com/urfave/cli/v2 from 2.4.0 to 2.5.1 (#2074)

  * chore(os): updated fanal version and alpine distroless test (#2086)

  * chore(deps): bump github.com/CycloneDX/cyclonedx-go from 0.5.1 to 0.5.2
       (#2075)

  * chore(deps): bump github.com/samber/lo from 1.16.0 to 1.19.0 (#2076)

  * feat(report): add support for SPDX (#2059)

  * chore(deps): bump actions/setup-go from 2 to 3 (#2073)

  * chore(deps): bump actions/cache from 3.0.1 to 3.0.2 (#2071)

  * chore(deps): bump golang from 1.18.0 to 1.18.1 (#2069)

  * chore(deps): bump actions/stale from 4 to 5 (#2070)

  * chore(deps): bump sigstore/cosign-installer from 2.0.0 to 2.3.0 (#2072)

  * chore(deps): bump github.com/open-policy-agent/opa from 0.39.0 to 0.40.0
       (#2079)

  * chore: app version 0.27.0 (#2046)

  * fix(misconf): added to skip conf files if their scanning is not enabled
       (#2066)

  * docs(secret) fix rule path in docs (#2061)

  * docs: change from go.sum to go.mod (#2056)
  Update to version 0.27.1:

  * chore(deps): bump github.com/CycloneDX/cyclon ...

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

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.28.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.28.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
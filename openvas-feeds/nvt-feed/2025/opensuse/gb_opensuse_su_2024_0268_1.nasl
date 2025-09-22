# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0268.1");
  script_cve_id("CVE-2023-42363", "CVE-2024-35192", "CVE-2024-6257");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 05:06:49 +0000 (Thu, 30 Nov 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0268-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0268-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6XAQOEGAUMX4BBTNYDJHKA4H3VD5H2PQ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227022");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy' package(s) announced via the openSUSE-SU-2024:0268-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"trivy was updated to fix the following issues:

Update to version 0.54.1:

* fix(flag): incorrect behavior for deprected flag `--clear-cache` [backport: release/v0.54] (#7285)
* fix(java): Return error when trying to find a remote pom to avoid segfault [backport: release/v0.54] (#7283)
* fix(plugin): do not call GitHub content API for releases and tags [backport: release/v0.54] (#7279)
* docs: update ecosystem page reporting with plopsec.com app (#7262)
* feat(vex): retrieve VEX attestations from OCI registries (#7249)
* feat(sbom): add image labels into `SPDX` and `CycloneDX` reports (#7257)
* refactor(flag): return error if both `--download-db-only` and `--download-java-db-only` are specified (#7259)
* fix(nodejs): detect direct dependencies when using `latest` version for files `yarn.lock` + `package.json` (#7110)
* chore: show VEX notice for OSS maintainers in CI environments (#7246)
* feat(vuln): add `--pkg-relationships` (#7237)
* docs: show VEX cli pages + update config file page for VEX flags (#7244)
* fix(dotnet): show `nuget package dir not found` log only when checking `nuget` packages (#7194)
* feat(vex): VEX Repository support (#7206)
* fix(secret): skip regular strings contain secret patterns (#7182)
* feat: share build-in rules (#7207)
* fix(report): hide empty table when all secrets/license/misconfigs are ignored (#7171)
* fix(cli): error on missing config file (#7154)
* fix(secret): update length of `hugging-face-access-token` (#7216)
* feat(sbom): add vulnerability support for SPDX formats (#7213)
* fix(secret): trim excessively long lines (#7192)
* chore(vex): update subcomponents for CVE-2023-42363/42364/42365/42366 (#7201)
* fix(server): pass license categories to options (#7203)
* feat(mariner): Add support for Azure Linux (#7186)
* docs: updates config file (#7188)
* refactor(fs): remove unused field for CompositeFS (#7195)
* fix: add missing platform and type to spec (#7149)
* feat(misconf): enabled China configuration for ACRs (#7156)
* fix: close file when failed to open gzip (#7164)
* docs: Fix PR documentation to use GitHub Discussions, not Issues (#7141)
* docs(misconf): add info about limitations for terraform plan json (#7143)
* chore: add VEX for Trivy images (#7140)
* chore: add VEX document and generator for Trivy (#7128)
* fix(misconf): do not evaluate TF when a load error occurs (#7109)
* feat(cli): rename `--vuln-type` flag to `--pkg-types` flag (#7104)
* refactor(secret): move warning about file size after `IsBinary` check (#7123)
* feat: add openSUSE tumbleweed detection and scanning (#6965)
* test: add missing advisory details for integration tests database (#7122)
* fix: Add dependencyManagement exclusions to the child exclusions (#6969)
* fix: ignore nodes when listing permission is not allowed (#7107)
* fix(java): use `go-mvn-version` to remove `Package` duplicates (#7088)
* refactor(secret): add warning about large files ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'trivy' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.54.1~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02121.1");
  script_cve_id("CVE-2025-22872");
  script_tag(name:"creation_date", value:"2025-06-30 04:14:41 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502121-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241802");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040492.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'helm' package(s) announced via the SUSE-SU-2025:02121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for helm fixes the following issues:

Update to version 3.18.3:

 * build(deps): bump golang.org/x/crypto from 0.38.0 to 0.39.0
 6838ebc (dependabot[bot])
 * fix: user username password for login 5b9e2f6 (Terry Howe)
 * Update pkg/registry/transport.go 2782412 (Terry Howe)
 * Update pkg/registry/transport.go e66cf6a (Terry Howe)
 * fix: add debug logging to oci transport 191f05c (Terry Howe)

Update to version 3.18.2:

 * fix: legacy docker support broken for login 04cad46 (Terry
 Howe)
 * Handle an empty registry config file. bc9f8a2 (Matt Farina)

Update to version 3.18.1:

 * Notes:

 - This release fixes regressions around template generation and
 OCI registry interaction in 3.18.0
 - There are at least 2 known regressions unaddressed in this
 release. They are being worked on.
 - Empty registry configuration files. When the file exists
 but it is empty.
 - Login to Docker Hub on some domains fails.

 * Changelog

 - fix(client): skipnode utilization for PreCopy
 - fix(client): layers now returns manifest - remove duplicate
 from descriptors
 - fix(client): return nil on non-allowed media types
 - Prevent fetching newReference again as we have in calling
 method
 - Prevent failure when resolving version tags in oras memory
 store
 - Update pkg/plugin/plugin.go
 - Update pkg/plugin/plugin.go
 - Wait for Helm v4 before raising when platformCommand and
 Command are set
 - Fix 3.18.0 regression: registry login with scheme
 - Revert 'fix (helm) : toToml` renders int as float [ backport
 to v3 ]'

Update to version 3.18.0 (bsc#1241802, CVE-2025-22872):

 * Notable Changes

 - Add support for JSON Schema 2020
 - Enabled cpu and memory profiling
 - Add hook annotation to output hook logs to client on error

 * Changelog

 - build(deps): bump the k8s-io group with 7 updates
 - fix: govulncheck workflow
 - bump version to v3.18.0
 - fix:add proxy support when mTLS configured
 - docs: Note about http fallback for OCI registries
 - Bump net package to avoid CVE on dev-v3
 - Bump toml
 - backport #30677to dev3
 - build(deps): bump github.com/rubenv/sql-migrate from 1.7.2 to
 1.8.0
 - Add install test for TakeOwnership flag
 - Fix --take-ownership
 - build(deps): bump github.com/rubenv/sql-migrate from 1.7.1 to
 1.7.2
 - build(deps): bump golang.org/x/crypto from 0.36.0 to 0.37.0
 - build(deps): bump golang.org/x/term from 0.30.0 to 0.31.0
 - Testing text bump
 - Permit more Go version and not only 1.23.8
 - Bumps github.com/distribution/distribution/v3 from 3.0.0-rc.3
 to 3.0.0
 - Unarchiving fix
 - Fix typo
 - Report as debug log, the time spent waiting for resources
 - build(deps): bump github.com/containerd/containerd from
 1.7.26 to 1.7.27
 - Update pkg/registry/fallback.go
 - automatic fallback to http
 - chore(oci): upgrade to ORAS v2
 - Updating to 0.37.0 for x/net
 - build(deps): bump the k8s-io group with 7 updates
 - build(deps): bump golang.org/x/crypto ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'helm' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.18.3~150000.1.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-bash-completion", rpm:"helm-bash-completion~3.18.3~150000.1.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-fish-completion", rpm:"helm-fish-completion~3.18.3~150000.1.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-zsh-completion", rpm:"helm-zsh-completion~3.18.3~150000.1.50.1", rls:"openSUSELeap15.6"))) {
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

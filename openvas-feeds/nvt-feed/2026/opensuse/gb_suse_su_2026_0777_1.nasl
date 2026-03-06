# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0777.1");
  script_cve_id("CVE-2025-11065", "CVE-2025-58181", "CVE-2026-22703", "CVE-2026-22772", "CVE-2026-23991", "CVE-2026-23992", "CVE-2026-24122", "CVE-2026-24137", "CVE-2026-26958");
  script_tag(name:"creation_date", value:"2026-03-05 04:35:07 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 16:02:19 +0000 (Tue, 17 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0777-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260777-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258612");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024541.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2026:0777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cosign fixes the following issues:

Update to version 3.0.5 (jsc#SLE-23879).

Security issues fixed:

- CVE-2025-11065: github.com/go-viper/mapstructure/v2: sensitive Information leak in logs (bsc#1250620).
- CVE-2025-58181: golang.org/x/crypto/ssh: invalidated number of mechanisms can cause unbounded memory consumption
 (bsc#1253913).
- CVE-2026-22703: Verification accepts any valid Rekor entry under certain conditions (bsc#1256496).
- CVE-2026-22772: github.com/sigstore/fulcio: bypass MetaIssuer URL validation bypass can trigger SSRF to arbitrary
 internal services (bsc#1256562).
- CVE-2026-23991: github.com/theupdateframework/go-tuf/v2: denial of service due to invalid TUF metadata JSON returned
 by TUF repository (bsc#1257080).
- CVE-2026-23992: github.com/theupdateframework/go-tuf/v2: unauthorized modification to TUF metadata files due to a
 compromised or misconfigured TUF repository (bsc#1257085).
- CVE-2026-24122: improper validation of certificates that outlive expired CA certificates (bsc#1258542).
- CVE-2026-24137: github.com/sigstore/sigstore/pkg/tuf: legacy TUF client allows for arbitrary file writes with target
 cache path traversal (bsc#1257139).
- CVE-2026-26958: filippo.io/edwards25519: failure to initialize receiver in MultiScalarMult can produce invalid results
 and lead to undefined behavior (bsc#1258612).

Other updates and bugfixes:

* chore(deps): bump google.golang.org/api from 0.260.0 to 0.264.0 (#4679)
* chore(deps): bump github.com/sigstore/rekor-tiles/v2 from 2.0.1 to 2.1.0 (#4670)
* chore(deps): bump filippo.io/edwards25519 from 1.1.0 to 1.1.1 (#4712)
* chore(deps): bump gitlab.com/gitlab-org/api/client-go (#4680)
* chore(deps): bump the gomod group across 1 directory with 4 updates (#4702)
* chore(deps): bump the actions group with 3 updates (#4703)
* update golang builder to use go1.25.7 (#4687)
* update golangci-lint to v2.8.x (#4688)
* Support DSSE signing conformance test (#4685)
* chore(deps): bump the actions group across 1 directory with 8 updates (#4689)
* Deprecate rekor-entry-type flag (#4691)
* Deprecate cosign triangulate (#4676)
* Deprecate cosign copy (#4681)
* Enforce TSA requirement for Rekor v2, Fuclio signing (#4683)
* chore(deps): bump github.com/theupdateframework/go-tuf/v2 (#4668)
* chore(deps): bump golang from 1.25.5 to 1.25.6 in the all group (#4673)
* Automatically require signed timestamp with Rekor v2 entries (#4666)
* Fix syntax issue in conformance test, update nightly (#4664)
* Add mTLS support for TSA client connections when signing with a signing config (#4620)
* fix: avoid panic on malformed tlog entry body (#4652)
* Verify validity of chain rather than just certificate (#4663)
* Allow --local-image with --new-bundle-format for v2 and v3 signatures (#4626)
* chore(deps): bump the gomod group across 1 directory with 3 updates (#4662)
* Bump sigstore/sigstore to resolve GHSA (#4660)
* Gracefully ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cosign' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~3.0.5~150400.3.35.1", rls:"openSUSELeap15.6"))) {
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

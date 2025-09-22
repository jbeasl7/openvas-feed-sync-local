# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0430.1");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0430-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0430-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240430-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017891.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2024:0430-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Fix race condition on verification with multiple signatures attached to image (#3486)
* fix(clean): Fix clean cmd for private registries (#3446)
* Fixed BYO PKI verification (#3427)

Features:

* Allow for option in cosign attest and attest-blob to upload attestation as supported in Rekor (#3466)
* Add support for OpenVEX predicate type (#3405)

Documentation:

* Resolves #3088: `version` sub-command expected behaviour documentation and testing (#3447)
* add examples for cosign attach signature cmd (#3468)

Misc:

* Remove CertSubject function (#3467)
* Use local rekor and fulcio instances in e2e tests (#3478)

- bumped embedded golang.org/x/crypto/ssh to fix the Terrapin attack CVE-2023-48795 (bsc#1218207)

Updated to 2.2.2 (jsc#SLE-23879):

v2.2.2 adds a new container with a shell,
gcr.io/projectsigstore/cosign:vx.y.z-dev, in addition to the existing container gcr.io/projectsigstore/cosign:vx.y.z without a shell.

For private deployments, we have also added an alias for
--insecure-skip-log, --private-infrastructure.

Bug Fixes:

* chore(deps): bump github.com/sigstore/sigstore from 1.7.5 to 1.7.6 (#3411) which fixes a bug with using Azure KMS
* Don't require CT log keys if using a key/sk (#3415)
* Fix copy without any flag set (#3409)
* Update cosign generate cmd to not include newline (#3393)
* Fix idempotency error with signing (#3371)

Features:

* Add --yes flag cosign import-key-pair to skip the overwrite confirmation. (#3383)
* Use the timeout flag value in verify* commands. (#3391)
* add --private-infrastructure flag (#3369)

Container Updates:

* Bump builder image to use go1.21.4 and add new cosign image tags with shell (#3373)

Documentation:

* Update SBOM_SPEC.md (#3358)

- CVE-2023-48795: Fixed the Terrapin attack in embedded golang.org/x/crypto/ssh (bsc#1218207).");

  script_tag(name:"affected", value:"'cosign' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.2.3~150400.3.17.1", rls:"openSUSELeap15.5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0460.1");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0460-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0460-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240460-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218207");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017909.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rekor' package(s) announced via the SUSE-SU-2024:0460-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update contact for code of conduct (#1720)
 - Fix panic when parsing SSH SK pubkeys (#1712)
 - Correct index creation (#1708)
 - docs: fixzes a small typo on the readme (#1686)
 - chore: fix backfill-redis Makefile target (#1685)

Updated to rekor 1.3.0 (jsc#SLE-23476):

 - Update openapi.yaml (#1655)
 - pass transient errors through retrieveLogEntry (#1653)
 - return full entryID on HTTP 409 responses (#1650)
 - feat: Support publishing new log entries to Pub/Sub topics (#1580)
 - Change values of Identity.Raw, add fingerprints (#1628)
 - Extract all subjects from SANs for x509 verifier (#1632)
 - Fix type comment for Identity struct (#1619)
 - Refactor Identities API (#1611)
 - Refactor Verifiers to return multiple keys (#1601)
 - Update checkpoint link (#1597)
 - Use correct log index in inclusion proof (#1599)
 - remove instrumentation library (#1595)

Updated to rekor 1.2.2 (jsc#SLE-23476):

 - pass down error with message instead of nil
 - swap killswitch for 'docker-compose restart'

- CVE-2023-48795: Fixed Terrapin attack in embedded golang.org/x/crypto/ssh (bsc#1218207).");

  script_tag(name:"affected", value:"'rekor' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"rekor", rpm:"rekor~1.3.5~150400.4.19.1", rls:"openSUSELeap15.5"))) {
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

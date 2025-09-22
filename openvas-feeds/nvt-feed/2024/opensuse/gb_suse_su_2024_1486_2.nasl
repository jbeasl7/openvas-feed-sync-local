# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856365");
  script_cve_id("CVE-2024-29902", "CVE-2024-29903");
  script_tag(name:"creation_date", value:"2024-08-20 04:07:57 +0000 (Tue, 20 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 15:40:24 +0000 (Thu, 09 Jan 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1486-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1486-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241486-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222837");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019246.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cosign' package(s) announced via the SUSE-SU-2024:1486-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cosign fixes the following issues:

- CVE-2024-29902: Fixed denial of service on host machine via remote image with a malicious attachments (bsc#1222835)
- CVE-2024-29903: Fixed denial of service on host machine via malicious software artifacts (bsc#1222837)

Other fixes:
- Updated to 2.2.4 (jsc#SLE-23879)
 * Fixes for GHSA-88jx-383q-w4qc and GHSA-95pr-fxf5-86gv (#3661)
 * ErrNoSignaturesFound should be used when there is no signature attached to an image. (#3526)
 * fix semgrep issues for dgryski.semgrep-go ruleset (#3541)
 * Honor creation timestamp for signatures again (#3549)
 * Features
 * Adds Support for Fulcio Client Credentials Flow, and Argument to Set Flow Explicitly (#3578)");

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

  if(!isnull(res = isrpmvuln(pkg:"cosign", rpm:"cosign~2.2.4~150400.3.20.1", rls:"openSUSELeap15.6"))) {
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

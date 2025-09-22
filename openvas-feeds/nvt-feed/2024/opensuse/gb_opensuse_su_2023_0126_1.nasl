# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833613");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-46165");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-13 16:26:07 +0000 (Tue, 13 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:01:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for syncthing (openSUSE-SU-2023:0126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0126-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FSIGQKHWF6QOVLGHNMHBJX6N46RVSK5D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'syncthing'
  package(s) announced via the openSUSE-SU-2023:0126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for syncthing fixes the following issues:

  - Update to 1.13.5

  * This release fixes CVE-2022-46165 Cross-site Scripting (XSS) in Web
         GUI

  * Bugfixes:

         #8503: 'syncthing cli config devices add' reflect error when using

  - -addresses flag #8764: Ignore patterns creating during folder addition
     are not loaded #8778: Tests fail on Windows with Go 1.20 #8779: Test
     cleanup fails all model tests on Windows on Go 1.20 #8859: Incorrect
     handling of path for auto accepted folder

  * Other issues:

         #8799: 'fatal error: checkptr: converted pointer straddles multiple
     allocations' in crypto tests

  - Update to 1.23.4

  - Bugfixes:

         #8851: 'Running global migration to fix encryption file sizes' on
     every start

  - Update to 1.23.3

  * Bugfixes:

         #5408: Selection of time in versions GUI not possible without editing
     the string inside the textfield #8277: Mutual encrypted sharing doesn't
     work (both sides with password) #8556: Increased file size when sharing
     between encrypted devices #8599: Key generation at connect time is slow
     for encrypted connections

  * Enhancements:

         #7859: Allow sub-second watcher delay (use case: remote development)

  * Other issues:

         #8828: cmd/stdiscosrv: TestDatabaseGetSet flake

  - Adding a desktop file for the Web UI

  - Update to 1.23.2

  * Bugfixes:

         #8749: Relay listener does not restart sometimes

  * Enhancements:

         #8660: GUI editor for xattr filter patterns #8781: gui: Remove
     duplicate Spanish translation

  * Other issues:

         #8768: Update quic-go for Go 1.20");

  script_tag(name:"affected", value:"'syncthing' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"syncthing", rpm:"syncthing~1.23.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syncthing-relaysrv", rpm:"syncthing-relaysrv~1.23.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syncthing", rpm:"syncthing~1.23.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syncthing-relaysrv", rpm:"syncthing-relaysrv~1.23.5~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
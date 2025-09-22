# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.2568181009709");
  script_cve_id("CVE-2023-52424");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-256818da09)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-256818da09");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-256818da09");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294016");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328735");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328777");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iwd, libell' package(s) announced via the FEDORA-2024-256818da09 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"iwd 3.3:

 Fix issue with handling External Authentication.

iwd 3.2:

 Fix issue with GCC 15 and -std=c23 build errors.
 Add support for using PMKSA over SAE if available.
 Add support for HighUtilization/StationCount thresholds.
 Add support for disabling Multicast RX option.

ell 0.71:

 Fix issue with GCC 15 and -std=c23 build errors.

ell 0.70:

 Add support for helper function for safe memcpy.");

  script_tag(name:"affected", value:"'iwd, libell' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"iwd", rpm:"iwd~3.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debuginfo", rpm:"iwd-debuginfo~3.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debugsource", rpm:"iwd-debugsource~3.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell", rpm:"libell~0.71~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debuginfo", rpm:"libell-debuginfo~0.71~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-debugsource", rpm:"libell-debugsource~0.71~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libell-devel", rpm:"libell-devel~0.71~1.fc41", rls:"FC41"))) {
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

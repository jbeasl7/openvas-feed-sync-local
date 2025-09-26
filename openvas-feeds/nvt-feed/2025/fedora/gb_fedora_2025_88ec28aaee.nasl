# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8810199289797101101");
  script_cve_id("CVE-2025-8114", "CVE-2025-8277");
  script_tag(name:"creation_date", value:"2025-09-25 04:05:01 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-24 15:15:27 +0000 (Thu, 24 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-88ec28aaee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-88ec28aaee");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-88ec28aaee");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2383236");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2394021");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2394047");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the FEDORA-2025-88ec28aaee advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release fixing the following security weaknesses (CVE-2025-8114, CVE-2025-8277)");

  script_tag(name:"affected", value:"'libssh' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.11.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.11.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-debuginfo", rpm:"libssh-debuginfo~0.11.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-debugsource", rpm:"libssh-debugsource~0.11.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.11.3~1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10194782101579");
  script_cve_id("CVE-2025-1914", "CVE-2025-1915", "CVE-2025-1916", "CVE-2025-1917", "CVE-2025-1918", "CVE-2025-1919", "CVE-2025-1921", "CVE-2025-1922", "CVE-2025-1923");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-e94782e579)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-e94782e579");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-e94782e579");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349973");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349974");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350032");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350034");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350035");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350036");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350037");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350038");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350039");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350040");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350041");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350042");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2350043");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-e94782e579 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 134.0.6998.35

 * CVE-2025-1914: Out of bounds read in V8
 * CVE-2025-1915: Improper Limitation of a Pathname to a Restricted Directory in DevTools
 * CVE-2025-1916: Use after free in Profiles
 * CVE-2025-1917: Inappropriate Implementation in Browser UI
 * CVE-2025-1918: Out of bounds read in PDFium
 * CVE-2025-1919: Out of bounds read in Media
 * CVE-2025-1921: Inappropriate Implementation in Media Stream
 * CVE-2025-1922: Inappropriate Implementation in Selection
 * CVE-2025-1923: Inappropriate Implementation in Permission Prompts");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~134.0.6998.35~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~134.0.6998.35~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~134.0.6998.35~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~134.0.6998.35~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~134.0.6998.35~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~134.0.6998.35~1.fc41", rls:"FC41"))) {
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

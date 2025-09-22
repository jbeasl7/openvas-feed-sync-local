# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8971897597077");
  script_cve_id("CVE-2024-12224", "CVE-2025-4574");
  script_tag(name:"creation_date", value:"2025-06-25 04:11:37 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 22:15:25 +0000 (Tue, 13 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-8a18a5a077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8a18a5a077");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8a18a5a077");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366549");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366551");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370580");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370586");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'atuin, awatcher, gotify-desktop, mirrorlist-server' package(s) announced via the FEDORA-2025-8a18a5a077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebuild applications to apply two recent security updates:

- build with idna 1.0.0+ to address CVE-2024-12224 (idna accepts Punycode labels that do not produce any non-ASCII when decoded)
- build with crossbeam-channel 0.5.15+ to address CVE-2025-4574 (potential double-free on Drop)");

  script_tag(name:"affected", value:"'atuin, awatcher, gotify-desktop, mirrorlist-server' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"atuin", rpm:"atuin~18.3.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-all-users", rpm:"atuin-all-users~18.3.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-debuginfo", rpm:"atuin-debuginfo~18.3.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-debugsource", rpm:"atuin-debugsource~18.3.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aw-awatcher", rpm:"aw-awatcher~0.3.1~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aw-awatcher-debuginfo", rpm:"aw-awatcher-debuginfo~0.3.1~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"awatcher", rpm:"awatcher~0.3.1~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"awatcher-debugsource", rpm:"awatcher-debugsource~0.3.1~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop", rpm:"gotify-desktop~1.3.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop-debuginfo", rpm:"gotify-desktop-debuginfo~1.3.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop-debugsource", rpm:"gotify-desktop-debugsource~1.3.7~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server", rpm:"mirrorlist-server~3.0.7~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debuginfo", rpm:"mirrorlist-server-debuginfo~3.0.7~7.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debugsource", rpm:"mirrorlist-server-debugsource~3.0.7~7.fc42", rls:"FC42"))) {
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

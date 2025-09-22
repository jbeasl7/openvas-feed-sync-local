# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.39918102101010093");
  script_cve_id("CVE-2024-12254", "CVE-2024-9287");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 18:47:16 +0000 (Mon, 10 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3c18fe0d93)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3c18fe0d93");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3c18fe0d93");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2321657");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330562");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330927");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331665");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122792");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/124651");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/125140");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcomps, libdnf, python3-docs, python3.13' package(s) announced via the FEDORA-2024-3c18fe0d93 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the first maintenance release of Python 3.13
====================================================

Python 3.13 is the newest major release of the Python programming language, and it contains many new features and optimizations compared to Python 3.12. 3.13.1 is the latest maintenance release, containing almost 400 bugfixes, build improvements and documentation changes since 3.13.0.

Security content in this release
--------------------------------

- [gh-122792]([link moved to references]): Changed IPv4-mapped `ipaddress.IPv6Address` to consistently use the mapped IPv4 address value for deciding properties. Properties which have their behavior fixed are `is_multicast`, `is_reserved`, `is_link_local`, `is_global`, and `is_unspecified`.
- CVE-2024-9287: [gh-124651]([link moved to references]): Properly quote template strings in `venv` activation scripts.
- [gh-125140]([link moved to references]): Remove the current directory from sys.path when using PyREPL.
- CVE-2024-12254: Unbounded memory buffering in `SelectorSocketTransport.writelines()` fixed.

libdnf and libcomps fixes
====================

- Fix segfaults in iterators (Python 3.13.1 made this crash happen in regular usage)");

  script_tag(name:"affected", value:"'libcomps, libdnf, python3-docs, python3.13' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcomps", rpm:"libcomps~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcomps-debuginfo", rpm:"libcomps-debuginfo~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcomps-debugsource", rpm:"libcomps-debugsource~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcomps-devel", rpm:"libcomps-devel~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcomps-doc", rpm:"libcomps-doc~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf", rpm:"libdnf~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-debuginfo", rpm:"libdnf-debuginfo~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-debugsource", rpm:"libdnf-debugsource~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdnf-devel", rpm:"libdnf-devel~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libcomps-doc", rpm:"python-libcomps-doc~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-unversioned-command", rpm:"python-unversioned-command~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-debug", rpm:"python3-debug~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-devel", rpm:"python3-devel~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.13.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hawkey", rpm:"python3-hawkey~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hawkey-debuginfo", rpm:"python3-hawkey-debuginfo~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-idle", rpm:"python3-idle~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libcomps", rpm:"python3-libcomps~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libcomps-debuginfo", rpm:"python3-libcomps-debuginfo~0.1.21~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf", rpm:"python3-libdnf~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libdnf-debuginfo", rpm:"python3-libdnf-debuginfo~0.73.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libs", rpm:"python3-libs~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-test", rpm:"python3-test~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-tkinter", rpm:"python3-tkinter~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13", rpm:"python3.13~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-debuginfo", rpm:"python3.13-debuginfo~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-debugsource", rpm:"python3.13-debugsource~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-freethreading", rpm:"python3.13-freethreading~3.13.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.13-freethreading-debug", rpm:"python3.13-freethreading-debug~3.13.1~2.fc41", rls:"FC41"))) {
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

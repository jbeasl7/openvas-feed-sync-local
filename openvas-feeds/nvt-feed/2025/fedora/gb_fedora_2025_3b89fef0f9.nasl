# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3988910210110201029");
  script_cve_id("CVE-2025-32049", "CVE-2025-4476", "CVE-2025-46420", "CVE-2025-46421", "CVE-2025-4945", "CVE-2025-4948", "CVE-2025-4969");
  script_tag(name:"creation_date", value:"2025-06-09 04:11:16 +0000 (Mon, 09 Jun 2025)");
  script_version("2025-06-10T05:40:17+0000");
  script_tag(name:"last_modification", value:"2025-06-10 05:40:17 +0000 (Tue, 10 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-19 16:15:36 +0000 (Mon, 19 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3b89fef0f9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3b89fef0f9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3b89fef0f9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357076");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361967");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361969");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366519");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366523");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367178");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367190");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367555");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367558");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-libsoup' package(s) announced via the FEDORA-2025-3b89fef0f9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for CVE-2025-4476, CVE-2025-4948, CVE-2025-4969, CVE-2025-46420, CVE-2025-46421, CVE-2025-4945");

  script_tag(name:"affected", value:"'mingw-libsoup' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-libsoup", rpm:"mingw-libsoup~2.74.3~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup", rpm:"mingw32-libsoup~2.74.3~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup-debuginfo", rpm:"mingw32-libsoup-debuginfo~2.74.3~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup", rpm:"mingw64-libsoup~2.74.3~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup-debuginfo", rpm:"mingw64-libsoup-debuginfo~2.74.3~12.fc41", rls:"FC41"))) {
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

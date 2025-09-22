# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1011027102988331022");
  script_cve_id("CVE-2025-26594", "CVE-2025-26595", "CVE-2025-26596", "CVE-2025-26597", "CVE-2025-26598", "CVE-2025-26599", "CVE-2025-26600", "CVE-2025-26601");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 16:15:39 +0000 (Tue, 25 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-ef7fb833f2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ef7fb833f2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ef7fb833f2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349366");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349369");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349372");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349375");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349378");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349455");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349461");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc' package(s) announced via the FEDORA-2025-ef7fb833f2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixes for xorg-x11-server CVEs.");

  script_tag(name:"affected", value:"'tigervnc' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-debuginfo", rpm:"tigervnc-debuginfo~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-debugsource", rpm:"tigervnc-debugsource~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-selinux", rpm:"tigervnc-selinux~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-debuginfo", rpm:"tigervnc-server-debuginfo~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-minimal-debuginfo", rpm:"tigervnc-server-minimal-debuginfo~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-module", rpm:"tigervnc-server-module~1.15.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-module-debuginfo", rpm:"tigervnc-server-module-debuginfo~1.15.0~2.fc42", rls:"FC42"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.985981634991000");
  script_cve_id("CVE-2025-43961", "CVE-2025-43962", "CVE-2025-43963", "CVE-2025-43964");
  script_tag(name:"creation_date", value:"2025-07-07 04:13:50 +0000 (Mon, 07 Jul 2025)");
  script_version("2025-07-07T05:42:05+0000");
  script_tag(name:"last_modification", value:"2025-07-07 05:42:05 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-08 16:54:54 +0000 (Thu, 08 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b5b1634cd0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b5b1634cd0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b5b1634cd0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2323675");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2335721");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342151");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361340");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361358");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361376");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361403");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'darktable' package(s) announced via the FEDORA-2025-b5b1634cd0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"5.2.0 release");

  script_tag(name:"affected", value:"'darktable' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"darktable", rpm:"darktable~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-debuginfo", rpm:"darktable-debuginfo~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-debugsource", rpm:"darktable-debugsource~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-basecurve", rpm:"darktable-tools-basecurve~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-basecurve-debuginfo", rpm:"darktable-tools-basecurve-debuginfo~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-noise", rpm:"darktable-tools-noise~5.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-noise-debuginfo", rpm:"darktable-tools-noise-debuginfo~5.2.0~1.fc41", rls:"FC41"))) {
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

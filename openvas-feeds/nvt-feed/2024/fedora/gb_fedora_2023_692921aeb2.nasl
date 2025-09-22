# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.69292197101982");
  script_cve_id("CVE-2023-49460", "CVE-2023-49462", "CVE-2023-49463", "CVE-2023-49464");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-11 17:31:56 +0000 (Mon, 11 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-692921aeb2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-692921aeb2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-692921aeb2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253562");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253563");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253565");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253566");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253567");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253568");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253575");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253576");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif' package(s) announced via the FEDORA-2023-692921aeb2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libheif-1.17.5-1.fc40.

##### **Changelog**

```
* Fri Dec 15 2023 Dominik Mierzejewski <dominik@greysector.net> - 1.17.5-2
- Update to 1.17.5 (rhbz#2244583)
- Backport fixes for: CVE-2023-49460 (rhbz#2253575, rhbz#2253576)
 CVE-2023-49462 (rhbz#2253567, rhbz#2253568)
 CVE-2023-49463 (rhbz#2253565, rhbz#2253566)
 CVE-2023-49464 (rhbz#2253562, rhbz#2253563)
- Simplify conditionals for rav1e and svt-av1 encoders
- Enable JPEG2000 and dav1d decoders/encoders

```");

  script_tag(name:"affected", value:"'libheif' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"heif-pixbuf-loader", rpm:"heif-pixbuf-loader~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heif-pixbuf-loader-debuginfo", rpm:"heif-pixbuf-loader-debuginfo~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif", rpm:"libheif~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-debuginfo", rpm:"libheif-debuginfo~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-debugsource", rpm:"libheif-debugsource~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-tools", rpm:"libheif-tools~1.17.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-tools-debuginfo", rpm:"libheif-tools-debuginfo~1.17.5~1.fc40", rls:"FC40"))) {
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

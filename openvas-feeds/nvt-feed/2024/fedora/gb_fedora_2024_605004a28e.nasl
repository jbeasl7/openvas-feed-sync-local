# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885721");
  script_cve_id("CVE-2024-24575", "CVE-2024-24577");
  script_tag(name:"creation_date", value:"2024-02-17 02:03:17 +0000 (Sat, 17 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 14:54:09 +0000 (Thu, 15 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-605004a28e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-605004a28e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-605004a28e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261321");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263096");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263101");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2_1.6' package(s) announced via the FEDORA-2024-605004a28e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.6.5

Resolves: CVE-2024-24577
Resolves: CVE-2024-24575");

  script_tag(name:"affected", value:"'libgit2_1.6' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"libgit2_1.6", rpm:"libgit2_1.6~1.6.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2_1.6-debuginfo", rpm:"libgit2_1.6-debuginfo~1.6.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2_1.6-debugsource", rpm:"libgit2_1.6-debugsource~1.6.5~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2_1.6-devel", rpm:"libgit2_1.6-devel~1.6.5~1.fc39", rls:"FC39"))) {
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

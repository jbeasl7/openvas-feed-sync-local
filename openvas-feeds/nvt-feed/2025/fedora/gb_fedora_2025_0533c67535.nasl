# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.05339967535");
  script_cve_id("CVE-2023-43907");
  script_tag(name:"creation_date", value:"2025-06-24 04:11:34 +0000 (Tue, 24 Jun 2025)");
  script_version("2025-06-24T05:41:22+0000");
  script_tag(name:"last_modification", value:"2025-06-24 05:41:22 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-03 20:57:20 +0000 (Tue, 03 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-0533c67535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-0533c67535");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-0533c67535");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359202");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'optipng' package(s) announced via the FEDORA-2025-0533c67535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 7.9.1");

  script_tag(name:"affected", value:"'optipng' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~7.9.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debuginfo", rpm:"optipng-debuginfo~7.9.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debugsource", rpm:"optipng-debugsource~7.9.1~1.fc41", rls:"FC41"))) {
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

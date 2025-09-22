# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886524");
  script_cve_id("CVE-2024-25629");
  script_tag(name:"creation_date", value:"2024-05-27 10:42:40 +0000 (Mon, 27 May 2024)");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 21:41:30 +0000 (Wed, 05 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-9963d77dcb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9963d77dcb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-9963d77dcb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265714");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c-ares' package(s) announced via the FEDORA-2024-9963d77dcb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"1.28.1 fixes a significant bug in 1.28.0.

----

Update to 1.28.0. Also fixes CVE-2024-25629.");

  script_tag(name:"affected", value:"'c-ares' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"c-ares", rpm:"c-ares~1.28.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debuginfo", rpm:"c-ares-debuginfo~1.28.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-debugsource", rpm:"c-ares-debugsource~1.28.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-ares-devel", rpm:"c-ares-devel~1.28.1~1.fc40", rls:"FC40"))) {
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

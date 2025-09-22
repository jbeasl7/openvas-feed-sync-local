# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886338");
  script_cve_id("CVE-2023-2794", "CVE-2023-4232", "CVE-2023-4233", "CVE-2023-4234", "CVE-2023-4235");
  script_tag(name:"creation_date", value:"2024-03-28 02:11:22 +0000 (Thu, 28 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-c42ea059d0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c42ea059d0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c42ea059d0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255387");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255388");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255394");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255395");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255397");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255399");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255400");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255402");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255403");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ofono' package(s) announced via the FEDORA-2024-c42ea059d0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to v2.5");

  script_tag(name:"affected", value:"'ofono' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"ofono", rpm:"ofono~2.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofono-debuginfo", rpm:"ofono-debuginfo~2.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofono-debugsource", rpm:"ofono-debugsource~2.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofono-devel", rpm:"ofono-devel~2.5~1.fc40", rls:"FC40"))) {
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

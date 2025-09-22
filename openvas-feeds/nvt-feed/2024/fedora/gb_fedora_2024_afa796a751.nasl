# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.971029779697751");
  script_cve_id("CVE-2024-21626", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"creation_date", value:"2024-10-28 04:08:30 +0000 (Mon, 28 Oct 2024)");
  script_version("2024-10-29T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 15:38:09 +0000 (Fri, 09 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-afa796a751)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-afa796a751");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-afa796a751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317465");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318187");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319020");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman-tui' package(s) announced via the FEDORA-2024-afa796a751 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"release 1.2.3");

  script_tag(name:"affected", value:"'podman-tui' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman-tui", rpm:"podman-tui~1.2.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tui-debuginfo", rpm:"podman-tui-debuginfo~1.2.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tui-debugsource", rpm:"podman-tui-debugsource~1.2.3~1.fc40", rls:"FC40"))) {
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

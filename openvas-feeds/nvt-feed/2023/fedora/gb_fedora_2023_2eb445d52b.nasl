# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885224");
  script_cve_id("CVE-2023-5367");
  script_tag(name:"creation_date", value:"2023-11-07 02:15:26 +0000 (Tue, 07 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 17:21:49 +0000 (Thu, 02 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-2eb445d52b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-2eb445d52b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-2eb445d52b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243076");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243091");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246029");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246137");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-Xwayland' package(s) announced via the FEDORA-2023-2eb445d52b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xwayland 23.2.2

----

Security fix for CVE-2023-5367");

  script_tag(name:"affected", value:"'xorg-x11-server-Xwayland' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland", rpm:"xorg-x11-server-Xwayland~23.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland-debuginfo", rpm:"xorg-x11-server-Xwayland-debuginfo~23.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland-debugsource", rpm:"xorg-x11-server-Xwayland-debugsource~23.2.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xwayland-devel", rpm:"xorg-x11-server-Xwayland-devel~23.2.2~1.fc39", rls:"FC39"))) {
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

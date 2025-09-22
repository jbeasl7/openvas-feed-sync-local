# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.91998997101512");
  script_cve_id("CVE-2024-0444", "CVE-2024-4453");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-01 13:58:59 +0000 (Fri, 01 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-919bc7e512)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-919bc7e512");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-919bc7e512");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283001");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292337");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) announced via the FEDORA-2024-919bc7e512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to gstreamer-1.22.9.

----

Backport fix for CVE-2024-0444.");

  script_tag(name:"affected", value:"'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1", rpm:"mingw-gstreamer1~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-bad-free", rpm:"mingw-gstreamer1-plugins-bad-free~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-base", rpm:"mingw-gstreamer1-plugins-base~1.22.9~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-good", rpm:"mingw-gstreamer1-plugins-good~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1", rpm:"mingw32-gstreamer1~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-debuginfo", rpm:"mingw32-gstreamer1-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free", rpm:"mingw32-gstreamer1-plugins-bad-free~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw32-gstreamer1-plugins-bad-free-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base", rpm:"mingw32-gstreamer1-plugins-base~1.22.9~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base-debuginfo", rpm:"mingw32-gstreamer1-plugins-base-debuginfo~1.22.9~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good", rpm:"mingw32-gstreamer1-plugins-good~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good-debuginfo", rpm:"mingw32-gstreamer1-plugins-good-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1", rpm:"mingw64-gstreamer1~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-debuginfo", rpm:"mingw64-gstreamer1-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free", rpm:"mingw64-gstreamer1-plugins-bad-free~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw64-gstreamer1-plugins-bad-free-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base", rpm:"mingw64-gstreamer1-plugins-base~1.22.9~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base-debuginfo", rpm:"mingw64-gstreamer1-plugins-base-debuginfo~1.22.9~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good", rpm:"mingw64-gstreamer1-plugins-good~1.22.9~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good-debuginfo", rpm:"mingw64-gstreamer1-plugins-good-debuginfo~1.22.9~1.fc39", rls:"FC39"))) {
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

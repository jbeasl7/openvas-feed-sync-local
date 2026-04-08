# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10161008101910210049");
  script_cve_id("CVE-2026-2920", "CVE-2026-2921", "CVE-2026-2922", "CVE-2026-2923", "CVE-2026-3081", "CVE-2026-3082", "CVE-2026-3083", "CVE-2026-3084", "CVE-2026-3085", "CVE-2026-3086");
  script_tag(name:"creation_date", value:"2026-04-06 04:59:34 +0000 (Mon, 06 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-e6d8e9fd49)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-e6d8e9fd49");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-e6d8e9fd49");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2447936");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448013");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448019");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448020");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448021");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448022");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448029");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448030");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448032");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448038");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) announced via the FEDORA-2026-e6d8e9fd49 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to gstreamer-1.26.11.");

  script_tag(name:"affected", value:"'mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1", rpm:"mingw-gstreamer1~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-bad-free", rpm:"mingw-gstreamer1-plugins-bad-free~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-base", rpm:"mingw-gstreamer1-plugins-base~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-good", rpm:"mingw-gstreamer1-plugins-good~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1", rpm:"mingw32-gstreamer1~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-debuginfo", rpm:"mingw32-gstreamer1-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free", rpm:"mingw32-gstreamer1-plugins-bad-free~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw32-gstreamer1-plugins-bad-free-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base", rpm:"mingw32-gstreamer1-plugins-base~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base-debuginfo", rpm:"mingw32-gstreamer1-plugins-base-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good", rpm:"mingw32-gstreamer1-plugins-good~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good-debuginfo", rpm:"mingw32-gstreamer1-plugins-good-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1", rpm:"mingw64-gstreamer1~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-debuginfo", rpm:"mingw64-gstreamer1-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free", rpm:"mingw64-gstreamer1-plugins-bad-free~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw64-gstreamer1-plugins-bad-free-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base", rpm:"mingw64-gstreamer1-plugins-base~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base-debuginfo", rpm:"mingw64-gstreamer1-plugins-base-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good", rpm:"mingw64-gstreamer1-plugins-good~1.26.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good-debuginfo", rpm:"mingw64-gstreamer1-plugins-good-debuginfo~1.26.11~1.fc43", rls:"FC43"))) {
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

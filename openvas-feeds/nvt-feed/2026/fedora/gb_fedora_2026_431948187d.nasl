# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.431948187100");
  script_cve_id("CVE-2025-43213", "CVE-2025-43214", "CVE-2025-43457", "CVE-2025-43511", "CVE-2025-46299", "CVE-2026-20608", "CVE-2026-20635", "CVE-2026-20636", "CVE-2026-20643", "CVE-2026-20644", "CVE-2026-20652", "CVE-2026-20664", "CVE-2026-20665", "CVE-2026-20676", "CVE-2026-20691", "CVE-2026-28857", "CVE-2026-28859", "CVE-2026-28871");
  script_tag(name:"creation_date", value:"2026-04-14 05:00:06 +0000 (Tue, 14 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 14:46:38 +0000 (Fri, 13 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-431948187d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-431948187d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-431948187d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449069");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449073");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449086");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449089");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449092");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449095");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449098");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449102");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449108");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449111");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2450634");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453064");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453067");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453070");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453073");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453076");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453079");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453082");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk' package(s) announced via the FEDORA-2026-431948187d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.52.1.

Notable changes from 2.50 to 2.52:

 * Make text look like in other browsers by blending in linear color space.
 * Improved rendering performance by using a different tile size depending on whether GPU rendering is enabled or not.
 * Improved composition scheduling to avoid blocking waiting for tile painting.
 * Improved performance of accelerated 2D canvas by recording operations for batched replay.
 * Improved async scrolling when main thread is busy by avoiding locks and rendering the scrollbars from the scrolling thread.
 * Enabled dynamic MSAA for accelerated 2D canvas rendering.
 * Improved text rendering performance
 * Videos with BT2100-PQ colorspace are now tone-mapped to SDR, ensuring colours do not appear washed out.
 * Added support for the Audio Output Devices API.
 * Added API to handle WebXR permission requests.
 * Added API to query the immersive session status.
 * Added initial API for web extensions.

Additional changes from 2.52.0 to 2.52.1:

 * Reduce the amount of useless MPRIS notifications produced by MediaSesion when the information about media being played is incomplete.
 * Add Sysprof marks for mouse events.
 * Fix MediaSession icon for iheart.com not being displayed.
 * Fix several crashes and rendering issues.
 * Translation updates: Georgian.");

  script_tag(name:"affected", value:"'webkitgtk' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1", rpm:"javascriptcoregtk4.1~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-debuginfo", rpm:"javascriptcoregtk4.1-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel", rpm:"javascriptcoregtk4.1-devel~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel-debuginfo", rpm:"javascriptcoregtk4.1-devel-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0", rpm:"javascriptcoregtk6.0~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-debuginfo", rpm:"javascriptcoregtk6.0-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel", rpm:"javascriptcoregtk6.0-devel~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel-debuginfo", rpm:"javascriptcoregtk6.0-devel-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-debuginfo", rpm:"webkit2gtk4.1-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel", rpm:"webkit2gtk4.1-devel~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel-debuginfo", rpm:"webkit2gtk4.1-devel-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-doc", rpm:"webkit2gtk4.1-doc~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-debugsource", rpm:"webkitgtk-debugsource~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-debuginfo", rpm:"webkitgtk6.0-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel", rpm:"webkitgtk6.0-devel~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel-debuginfo", rpm:"webkitgtk6.0-devel-debuginfo~2.52.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-doc", rpm:"webkitgtk6.0-doc~2.52.1~1.fc43", rls:"FC43"))) {
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

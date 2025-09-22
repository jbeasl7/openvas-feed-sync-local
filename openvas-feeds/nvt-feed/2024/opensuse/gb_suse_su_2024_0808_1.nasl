# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856032");
  script_cve_id("CVE-2022-41704", "CVE-2022-42890", "CVE-2022-44729", "CVE-2022-44730");
  script_tag(name:"creation_date", value:"2024-03-25 09:31:08 +0000 (Mon, 25 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 18:19:40 +0000 (Fri, 28 Oct 2022)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0808-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240808-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204709");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-March/034578.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlgraphics-batik' package(s) announced via the SUSE-SU-2024:0808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xmlgraphics-batik fixes the following issues:

- CVE-2022-41704: Fixed information disclosure vulnerability in Apache Batik (bsc#1204704).
- CVE-2022-42890: Fixed information disclosure vulnerability in Apache Batik (bsc#1204709).
- CVE-2022-44730: Fixed Server-Side Request Forgery.
- CVE-2022-44729: Fixed Server-Side Request Forgery.

Upgrade to version 1.17.");

  script_tag(name:"affected", value:"'xmlgraphics-batik' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik", rpm:"xmlgraphics-batik~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-css", rpm:"xmlgraphics-batik-css~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-demo", rpm:"xmlgraphics-batik-demo~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-javadoc", rpm:"xmlgraphics-batik-javadoc~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-rasterizer", rpm:"xmlgraphics-batik-rasterizer~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-slideshow", rpm:"xmlgraphics-batik-slideshow~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-squiggle", rpm:"xmlgraphics-batik-squiggle~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-svgpp", rpm:"xmlgraphics-batik-svgpp~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmlgraphics-batik-ttf2svg", rpm:"xmlgraphics-batik-ttf2svg~1.17~150200.4.7.1", rls:"openSUSELeap15.5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01811.1");
  script_cve_id("CVE-2025-31176", "CVE-2025-31177", "CVE-2025-31178", "CVE-2025-31179", "CVE-2025-31180", "CVE-2025-31181", "CVE-2025-3359");
  script_tag(name:"creation_date", value:"2025-06-06 04:10:08 +0000 (Fri, 06 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-07 13:15:43 +0000 (Mon, 07 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01811-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501811-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241684");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040132.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnuplot' package(s) announced via the SUSE-SU-2025:01811-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnuplot fixes the following issues:

- CVE-2025-31176: invalid read leads to segmentation fault on plot3d_points (bsc#1240325).
- CVE-2025-31177: improper bounds check leads to heap-buffer overflow on utf8_copy_one (bsc#1240326).
- CVE-2025-31178: unvalidated user input leads to segmentation fault on GetAnnotateString (bsc#1240327).
- CVE-2025-31179: improper verification of time values leads to segmentation fault on xstrftime (bsc#1240328).
- CVE-2025-31180: unchecked invalid pointer access leads to segmentation fault on CANVAS_text (bsc#1240329).
- CVE-2025-31181: double fclose() call leads to segmentation fault on X11_graphics (bsc#1240330).
- CVE-2025-3359: out-of-bounds read when parsing font names may lead to a segmentation fault (bsc#1241684).");

  script_tag(name:"affected", value:"'gnuplot' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gnuplot", rpm:"gnuplot~5.4.3~150400.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnuplot-doc", rpm:"gnuplot-doc~5.4.3~150400.3.3.1", rls:"openSUSELeap15.6"))) {
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

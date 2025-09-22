# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0604.1");
  script_cve_id("CVE-2019-20446");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 22:06:23 +0000 (Thu, 13 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0604-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200604-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162501");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-March/006583.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg' package(s) announced via the SUSE-SU-2020:0604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for librsvg to version 2.40.21 fixes the following issues:

librsvg was updated to version 2.40.21 fixing the following issues:

- CVE-2019-20446: Fixed an issue where a crafted SVG file with nested
 patterns can cause denial of service (bsc#1162501).
 NOTE: Librsvg now has limits on the number of loaded XML elements,
 and the number of referenced elements within an SVG document.
- Fixed a stack exhaustion with circular references in <use>
 elements.
- Fixed a denial-of-service condition from exponential explosion
 of rendered elements, through nested use of SVG 'use' elements in
 malicious SVGs.");

  script_tag(name:"affected", value:"'librsvg' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.40.21~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.40.21~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-32bit", rpm:"librsvg-2-2-32bit~2.40.21~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsvg-view", rpm:"rsvg-view~2.40.21~5.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.40.21~5.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.40.21~5.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-32bit", rpm:"librsvg-2-2-32bit~2.40.21~5.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsvg-view", rpm:"rsvg-view~2.40.21~5.9.1", rls:"SLES12.0SP5"))) {
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

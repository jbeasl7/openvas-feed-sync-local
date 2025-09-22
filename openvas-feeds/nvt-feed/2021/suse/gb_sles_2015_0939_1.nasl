# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0939.1");
  script_cve_id("CVE-2015-0255");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0939-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150939-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920969");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001403.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fltk, tigervnc' package(s) announced via the SUSE-SU-2015:0939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tigervnc and fltk were updated to fix security issues and non-security bugs.

This security issue was fixed:
- CVE-2015-0255: Information leak in the XkbSetGeometry request of X servers (bnc#915810).

These non-security issues were fixed:
- vncviewer-tigervnc does not display mouse cursor shape changes (bnc#908738).
- vnc module for Xorg fails to load on startup, module mismatch (bnc#911577).
- An Xvnc session may become unusable when user logs out (bnc#920969)

fltk was updated to fix one non-security issue:
- vncviewer-tigervnc does not display mouse cursor shape changes (bnc#908738).

Additionally tigervnc was updated to 1.4.1, the contained X server was updated to 1.15.2.");

  script_tag(name:"affected", value:"'fltk, tigervnc' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libfltk1", rpm:"libfltk1~1.3.2~10.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.4.1~32.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~1.4.1~32.1", rls:"SLES12.0"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1127.1");
  script_cve_id("CVE-2014-8092", "CVE-2015-3418");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 15:12:59 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1127-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151127-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928520");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001456.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2015:1127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The X Server was updated to fix 1 security issues and 4 bugs:

Security issues:
- CVE-2015-3418: Fixed a regression introduced by CVE-2014-8092 in
 PutImage that caused crashes when called with 0 height (bnc#928520).

Bugs fixed:
- Xephyr: Don't crash when no command line argument is specified
 The DDX specific command line parsing function only gets called if
 command line arguments are present. Therefore this function is not
 suitable to initialize mandatory global variables. Replace main()
 instead. (bnc#925022)
- Xephyr: Print default server display number if none is specified (bnc#925022)
- Xephyr: Fix broken image when endianess of client machine and host-Xserver differ
 The image is created in the native byte order of the machine Xephyr is
 rendered on however drawn in the image byte order of the Xephyr server.
 Correct byte order in the xcb_image_t structure and convert to native
 before updating the window.
 If depths of Xephyr and host server differ this is already taken care of
 by the depth conversion routine. (bnc#923229).
- Xephyr: Fix compile when debugging is enabled (bnc#925021)
- Xephyr: Fix screen image draw for the non-Glamor & non-XHSM case
 xcb_image_put() prints the entire image, therefore don't use an offset.
 (bnc#925019)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.6_1.15.2~28.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.6_1.15.2~28.4", rls:"SLES12.0"))) {
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

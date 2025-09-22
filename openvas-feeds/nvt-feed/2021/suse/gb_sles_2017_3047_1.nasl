# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3047.1");
  script_cve_id("CVE-2017-12176", "CVE-2017-12177", "CVE-2017-12178", "CVE-2017-12179", "CVE-2017-12180", "CVE-2017-12181", "CVE-2017-12182", "CVE-2017-12183", "CVE-2017-12184", "CVE-2017-12185", "CVE-2017-12186", "CVE-2017-12187", "CVE-2017-13721", "CVE-2017-13723");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-07 13:08:00 +0000 (Wed, 07 Feb 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3047-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173047-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063041");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003402.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2017:3047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server fixes several issues.

These security issues were fixed:

- CVE-2017-13721: Missing validation of shmseg resource id in Xext/XShm
 could lead to shared memory segments of other users beeing freed
 (bnc#1052984)
- CVE-2017-13723: A local denial of service via unusual characters in XkbAtomText and XkbStringText was fixed (bnc#1051150)
- CVE-2017-12184,CVE-2017-12185,CVE-2017-12186,CVE-2017-12187: Fixed
 unvalidated lengths in multiple extensions (bsc#1063034)
- CVE-2017-12183: Fixed some unvalidated lengths in the XFIXES
 extension. (bsc#1063035)
- CVE-2017-12180,CVE-2017-12181,CVE-2017-12182: Fixed various unvalidated
 lengths in the XFree86-VidMode/XFree86-DGA/XFree86-DRI extensions
 (bsc#1063037)
- CVE-2017-12179: Fixed an integer overflow and unvalidated length in
 (S)ProcXIBarrierReleasePointer in Xi (bsc#1063038)
- CVE-2017-12178: Fixed a wrong extra length check in
 ProcXIChangeHierarchy in Xi (bsc#1063039)
- CVE-2017-12177: Fixed an unvalidated variable-length request in
 ProcDbeGetVisualInfo (bsc#1063040)
- CVE-2017-12176: Fixed an unvalidated extra length in
 ProcEstablishConnection (bsc#1063041)


These non-security issues were fixed:

- Make colormap/gamma glue code work with the RandR extension disabled. This prevents it
 from crashing and showing wrong colors. (bsc#1061107)
- Recognize ssh as a remote client to fix launching applications remotely when using DRI3.
 (bsc#1022727)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.6_1.18.3~76.15.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.6_1.18.3~76.15.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.6_1.18.3~76.15.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.6_1.18.3~76.15.2", rls:"SLES12.0SP3"))) {
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

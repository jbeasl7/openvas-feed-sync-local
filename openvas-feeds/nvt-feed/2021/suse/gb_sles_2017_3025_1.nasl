# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3025.1");
  script_cve_id("CVE-2017-12176", "CVE-2017-12177", "CVE-2017-12178", "CVE-2017-12179", "CVE-2017-12180", "CVE-2017-12181", "CVE-2017-12182", "CVE-2017-12183", "CVE-2017-12184", "CVE-2017-12185", "CVE-2017-12186", "CVE-2017-12187", "CVE-2017-13723");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-07 13:08:00 +0000 (Wed, 07 Feb 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3025-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3025-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173025-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063041");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003399.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2017:3025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server provides several fixes.

These security issues were fixed:

- CVE-2017-13723: Prevent local DoS via unusual characters in XkbAtomText and
 XkbStringText (bsc#1051150).
- Improve the entropy when generating random data used in X.org server authorization
 cookies generation by using getentropy() and getrandom() when available (bsc#1025084)
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
 ProcEstablishConnection (bsc#1063041)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.4~27.122.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.4~27.122.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.4~27.122.16.1", rls:"SLES11.0SP4"))) {
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

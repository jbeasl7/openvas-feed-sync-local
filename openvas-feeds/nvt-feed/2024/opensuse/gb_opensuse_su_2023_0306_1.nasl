# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833256");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-4170");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 17:42:07 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:27 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rxvt (openSUSE-SU-2023:0306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0306-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HJFJQGRU5ZFB7SWTSO2FUE3CKDHSOPB7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rxvt'
  package(s) announced via the openSUSE-SU-2023:0306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rxvt-unicode fixes the following issues:

  - Update to version 9.31: (CVE-2022-4170 boo#1206069)

  - implement a fix for CVE-2022-4170 (reported and analyzed by David
         Leadbeater). While present in version 9.30, it should not be
         exploitable. It is exploitable in versions 9.25 and 9.26, at least,
         and allows anybody controlling output to the terminal to execute
         arbitrary code in the urxvt process.

  - the background extension no longer requires off focus fading support
         to be compiled in.

  - the confirm-paste extension now offers a choice between pasting the
         original or a sanitized version, and also frees up memory used to
         store the paste text immediately.

  - fix compiling without frills.

  - fix rewrapMode: never.

  - fix regression that caused urxvt to no longer emit responses to OSC
         color queries other than OSC 4 ones.

  - fix regression that caused urxvt to no longer process OSC 705.

  - restore CENTURY to be 1900 to 'improve' year parsing in urclock (or at
         least go back to the old interpretation) (based on an analysis by
         Tommy Pettersson).

  - exec_async (used e.g. by the matcher extension to spawn processes) now
         sets the URXVT_EXT_WINDOWID variable to the window id of the terminal.

  - implement -fps option/refreshRate resource to change the default 60 Hz
         maximum refresh limiter. I always wanted an fps
         option, but had to wait for a user requesting it.

  - new clickthrough extension.

  - perl now also requires Xext.

  - X region and shape extension functionality has been exposed to perl
         extensions.

  - RENDER extension no longer depends on ENABLE_XIM_ONTHESPOT.");

  script_tag(name:"affected", value:"'rxvt' package(s) on openSUSE Backports SLE-15-SP4, openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode-debuginfo", rpm:"rxvt-unicode-debuginfo~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode-debugsource", rpm:"rxvt-unicode-debugsource~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode-debuginfo", rpm:"rxvt-unicode-debuginfo~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode-debugsource", rpm:"rxvt-unicode-debugsource~9.31~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.31~bp154.2.9.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.31~bp154.2.9.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
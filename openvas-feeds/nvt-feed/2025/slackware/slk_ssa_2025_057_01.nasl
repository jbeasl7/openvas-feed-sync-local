# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.057.01");
  script_cve_id("CVE-2024-53920", "CVE-2025-1244");
  script_tag(name:"creation_date", value:"2025-02-27 04:04:46 +0000 (Thu, 27 Feb 2025)");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 15:15:18 +0000 (Wed, 12 Feb 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-057-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-057-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.396090");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-53920");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1244");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs' package(s) announced via the SSA:2025-057-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New emacs packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/emacs-30.1-i586-1_slack15.0.txz: Upgraded.
 This update fixes two security issues:
 Fix shell injection vulnerability in man.el (CVE-2025-1244).
 New user option 'trusted-content' to allow potentially dangerous features.
 This option lists those files and directories whose content Emacs should
 consider as sufficiently trusted to run any part of the code contained
 therein even without any explicit user request. For example, Flymake's
 backend for Emacs Lisp consults this option and disables itself with an
 'untrusted content' warning if the file is not listed.
 Emacs Lisp authors should note that a major or minor mode must never set
 this option to the ':all' value.
 This option is used to fix CVE-2024-53920.
 Thanks to pbslxw for the heads-up.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'emacs' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"emacs", ver:"30.1-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"emacs", ver:"30.1-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"emacs", ver:"30.1-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"emacs", ver:"30.1-x86_64-1", rls:"SLKcurrent"))) {
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

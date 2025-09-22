# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.136.02");
  script_cve_id("CVE-2024-32002", "CVE-2024-32004", "CVE-2024-32020", "CVE-2024-32021", "CVE-2024-32465");
  script_tag(name:"creation_date", value:"2024-05-16 04:10:22 +0000 (Thu, 16 May 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 20:40:28 +0000 (Thu, 23 May 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-136-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-136-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.446512");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32002");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32004");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32020");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32021");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-32465");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the SSA:2024-136-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New git packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/git-2.39.4-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 Recursive clones on case-insensitive filesystems that support symbolic
 links are susceptible to case confusion that can be exploited to
 execute just-cloned code during the clone operation.
 Repositories can be configured to execute arbitrary code during local
 clones. To address this, the ownership checks introduced in v2.30.3
 are now extended to cover cloning local repositories.
 Local clones may end up hardlinking files into the target repository's
 object database when source and target repository reside on the same
 disk. If the source repository is owned by a different user, then
 those hardlinked files may be rewritten at any point in time by the
 untrusted user.
 When cloning a local source repository that contains symlinks via the
 filesystem, Git may create hardlinks to arbitrary user-readable files
 on the same filesystem as the target repository in the objects/
 directory.
 It is supposed to be safe to clone untrusted repositories, even those
 unpacked from zip archives or tarballs originating from untrusted
 sources, but Git can be tricked to run arbitrary code as part of the
 clone.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'git' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.39.4-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.39.4-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.45.1-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"git", ver:"2.45.1-x86_64-1", rls:"SLKcurrent"))) {
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

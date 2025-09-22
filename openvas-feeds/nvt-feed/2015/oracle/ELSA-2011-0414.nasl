# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122201");
  script_cve_id("CVE-2011-1011");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0414");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0414.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'policycoreutils, selinux-policy' package(s) announced via the ELSA-2011-0414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"policycoreutils:

[2.0.83-19.8]
- Fix seunshare to work with /tmp content when SELinux context is not provided
Resolves: #679689

[2.0.83-19.7]
- put back correct chcon
- Latest fixes for seunshare

[2.0.83-19.6]
- Fix rsync command to work if the directory is old.
- Fix all tests
Resolves: #679689

[2.0.83-19.5]
- Add requires rsync and fix man page for seunshare

[2.0.83-19.4]
- fix to sandbox
 - Fix seunshare to use more secure handling of /tmp
 - Rewrite seunshare to make sure /tmp is mounted stickybit owned by root
 - Change to allow sandbox to run on nfs homedirs, add start python script
 - change default location of HOMEDIR in sandbox to /tmp/.sandbox_home_*
 - Move seunshare to sandbox package
 - Fix sandbox to show correct types in usage statement

selinux-policy:

[3.7.19-54.0.1.el6_0.5]
- Allow ocfs2 to be mounted with file_t type.

[3.7.19-54.el6_0.5]
- seunshare needs to be able to mounton nfs/cifs/fusefs homedirs
Resolves: #684918

[3.7.19-54.el6_0.4]
- Fix to sandbox
 * selinux-policy fixes for policycoreutils sandbox changes
 - Fix seunshare to use more secure handling of /tmp
 - Change to allow sandbox to run on nfs homedirs, add start python script");

  script_tag(name:"affected", value:"'policycoreutils, selinux-policy' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils", rpm:"policycoreutils~2.0.83~19.8.el6_0", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-gui", rpm:"policycoreutils-gui~2.0.83~19.8.el6_0", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-newrole", rpm:"policycoreutils-newrole~2.0.83~19.8.el6_0", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-python", rpm:"policycoreutils-python~2.0.83~19.8.el6_0", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-sandbox", rpm:"policycoreutils-sandbox~2.0.83~19.8.el6_0", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-doc", rpm:"selinux-policy-doc~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-mls", rpm:"selinux-policy-mls~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"selinux-policy-targeted", rpm:"selinux-policy-targeted~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1645.1");
  script_cve_id("CVE-2013-7041", "CVE-2015-3238");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-08-25 15:08:09 +0000 (Tue, 25 Aug 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1645-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1645-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161645-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962220");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002134.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the SUSE-SU-2016:1645-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pam fixes two security issues.

These security issues were fixed:
- CVE-2015-3238: pam_unix in conjunction with SELinux allowed for DoS attacks (bsc#934920).
- CVE-2013-7041: Compare password hashes case-sensitively (bsc#854480).

This non-security issue was fixed:
- bsc#962220: Don't fail when /var/log/btmp is corrupted");

  script_tag(name:"affected", value:"'pam' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.5~0.17.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-32bit", rpm:"pam-32bit~1.1.5~0.17.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.1.5~0.17.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-x86", rpm:"pam-x86~1.1.5~0.17.2", rls:"SLES11.0SP4"))) {
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

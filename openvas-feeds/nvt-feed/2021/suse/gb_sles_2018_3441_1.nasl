# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3441.1");
  script_cve_id("CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-03 15:37:26 +0000 (Wed, 03 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3441-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183441-1.html");
  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=12048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110723");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004791.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2018:3441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

Clamav was updated to version 0.100.2:

- CVE-2018-15378: Vulnerability in ClamAV's MEW
 unpacking feature that could allow an unauthenticated, remote
 attacker to cause a denial of service (DoS) condition on an
 affected device. (bsc#1110723)
- CVE-2018-14680, CVE-2018-14681, CVE-2018-14682:
 more fixes for embedded libmspack. (bsc#1103040)

* Make freshclam more robust against lagging signature mirrors.
* On-Access 'Extra Scanning', an opt-in minor feature of
 OnAccess scanning on Linux systems, has been disabled due to a
 known issue with resource cleanup OnAccessExtraScanning will
 be re-enabled in a future release when the issue is
 resolved. In the mean-time, users who enabled the feature in
 clamd.conf will see a warning informing them that the feature
 is not active. For details, see:
 [link moved to references]

- Restore exit code compatibility of freshclam with versions before
 0.100.0 when the virus database is already up to date
 (bsc#1104457).");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.2~0.20.18.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.2~0.20.18.1", rls:"SLES11.0SP4"))) {
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

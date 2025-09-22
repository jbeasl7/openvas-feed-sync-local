# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02501.1");
  script_cve_id("CVE-2024-38822", "CVE-2024-38823", "CVE-2024-38824", "CVE-2024-38825", "CVE-2025-22236", "CVE-2025-22237", "CVE-2025-22238", "CVE-2025-22239", "CVE-2025-22240", "CVE-2025-22241", "CVE-2025-22242", "CVE-2025-47287");
  script_tag(name:"creation_date", value:"2025-07-28 04:22:08 +0000 (Mon, 28 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-10 00:34:26 +0000 (Thu, 10 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02501-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02501-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502501-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244575");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040873.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2025:02501-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

- Security issues fixed:

 - CVE-2024-38822: Fixed Minion token validation (bsc#1244561)
 - CVE-2024-38823: Fixed server vulnerability to replay attacks when not using a TLS encrypted transport (bsc#1244564)
 - CVE-2024-38824: Fixed directory traversal vulnerability in recv_file method (bsc#1244565)
 - CVE-2024-38825: Fixed salt.auth.pki module authentication issue (bsc#1244566)
 - CVE-2025-22240: Fixed arbitrary directory creation or file deletion with GitFS (bsc#1244567)
 - CVE-2025-22236: Fixed Minion event bus authorization bypass (bsc#1244568)
 - CVE-2025-22241: Fixed the use of un-validated input in the VirtKey class (bsc#1244570)
 - CVE-2025-22237: Fixed exploitation of the 'on demand' pillar functionality (bsc#1244571)
 - CVE-2025-22238: Fixed the master's default cache vulnerability to a directory traversal attack (bsc#1244572)
 - CVE-2025-22239: Fixed the arbitrary event injection on the Salt Master (bsc#1244574)
 - CVE-2025-22242: Fixed a Denial of Service vulnerability through file read operation (bsc#1244575)
 - CVE-2025-47287: Fixed a Denial of Service vulnerability in Tornado logging behavior (bsc#1243268)

- Other bugs fixed:

 - Added subsystem filter to udev.exportdb (bsc#1236621)
 - Fixed Ubuntu 24.04 test failures
 - Fixed refresh of osrelease and related grains on Python 3.10+
 - Fixed issue requiring proper Python flavor for dependencies");

  script_tag(name:"affected", value:"'salt' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt-testsuite", rpm:"python3-salt-testsuite~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-transactional-update", rpm:"salt-transactional-update~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150500.4.55.1", rls:"openSUSELeap15.6"))) {
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

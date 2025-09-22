# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833477");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-8908", "CVE-2022-0860", "CVE-2023-22644");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 13:42:59 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:26 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for installation-images (SUSE-SU-2023:1831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1831-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7U534DMCZJNKHM2EZ6UDSUEQMW5GZHWP");

  script_tag(name:"summary", value:"The remote host is missing an update for the installation-images package(s) announced via the SUSE-SU-2023:1831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  cobbler:

  * CVE-2022-0860: Unbreak PAM authentication due to missing encode of user
      input in the PAM auth module of Cobbler (bsc#1197027)

  * Fix S390X auto-installation for cases where kernel options are longer than
      79 characters (bsc#1207308)

  * Switch packaging from patch based to Git tree based development

  * All patches that are being removed in this revision are contained in the new
      Git tree.

  guava:

  * Upgrade to guava 30.1.1

  * CVE-2020-8908: temp directory creation vulnerability in Guava versions prior
      to 30.0. (bsc#1179926)

  * Remove parent reference from ALL distributed pom files

  * Avoid version-less dependencies that can cause problems with some tools

  * Build the package with ant in order to prevent build cycles using a
      generated and customized ant build system

  * Produce with Java  = 9 binaries that are compatible with Java 8

  jsr-305:

  * Deliver jsr-305 to SUSE Manager as Guava dependency

  mgr-libmod:

  * Version 4.2.8-1

  * Ignore extra metadata fields for Liberty Linux (bsc#1208908)

  spacecmd:

  * Version 4.2.22-1

  * Display activation key details after executing the corresponding command
      (bsc#1208719)

  * Show targeted packages before actually removing them (bsc#1207830)

  * Fix spacecmd not showing any output for softwarechannel_diff and
      softwarechannel_errata_diff (bsc#1207352)

  spacewalk-backend:

  * Version 4.2.27-1

  * Fix the mgr-inter-sync not creating valid repository metadata when dealing
      with empty channels (bsc#1207829)

  * Fix issues with kickstart syncing on mirrorlist repositories

  * Do not sync .mirrorlist and other non needed files

  * reposync: catch local file not found urlgrabber error properly (bsc#1208288)

  spacewalk-client-tools:

  * Version 4.2.23-1

  * Update translation strings

  spacewalk-java:

  * Version 4.2.49-1

  * Refactor Java notification synchronize to avoid deadlocks (bsc#1209369)

  * Version 4.2.48-1

  * Prevent logging formula data (bsc#1209386)

  * Use gnu-jaf instead of jaf

  * Use reload4j instead of log4j or log4j12

  * Use slf4j-reload4j

  * Save scheduler user when creating Patch actions manually (bsc#1208321)

  * Add `mgr_server_is_uyuni` minion pillar item

  * Do not execute immediately Package Refresh action for the SSH minion
      (bsc#1208325)

  * Mark as failed actions that cannot be scheduled because earliest date is too

    Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'installation-images package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"jsr-305", rpm:"jsr-305~3.0.2~150200.3.7.5", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsr-305-javadoc", rpm:"jsr-305-javadoc~3.0.2~150200.3.7.5", rls:"openSUSELeap15.4"))) {
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

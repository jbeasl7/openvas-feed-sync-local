# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833676");
  script_cve_id("CVE-2023-4759");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:22 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 13:54:11 +0000 (Mon, 18 Sep 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4|openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0057-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240057-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215298");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.56");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.57");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.58");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.59");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.60");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.61");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.62");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.63");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.64");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.65");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.66");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.67");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.68");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.69");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.70");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.71");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.0");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.1");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.2");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.3");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.4");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.5");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.6");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.7");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.8");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.9");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017598.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse-jgit, jsch' package(s) announced via the SUSE-SU-2024:0057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for eclipse-jgit, jsch fixes the following issues:

Security fix:
- CVE-2023-4759: Fixed an arbitrary file overwrite which might have occurred with a specially crafted git repository and a case-insensitive filesystem. (bsc#1215298)

Other fixes:
jsch was updated to version 0.2.9:
- Added support for various algorithms
- Migrated from `com.jcraft:jsch` to `com.github.mwiede:jsch` fork (bsc#1211955):
 * Alias to the old artifact since the new one is drop-in
 replacement
 * Keep the old OSGi bundle symbolic name to avoid extensive
 patching of eclipse stack
- Updated to version 0.2.9:
 * For the full list of changes please consult the upstream changelogs below for each version updated:
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]

eclipse-jgit:

- Craft the jgit script from the real Main class of the jar file instead of using a jar launcher (bsc#1209646)");

  script_tag(name:"affected", value:"'eclipse-jgit, jsch' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jgit", rpm:"eclipse-jgit~5.11.0~150200.3.15.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jgit", rpm:"jgit~5.11.0~150200.3.15.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jgit-javadoc", rpm:"jgit-javadoc~5.11.0~150200.3.15.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch", rpm:"jsch~0.2.9~150200.11.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch-demo", rpm:"jsch-demo~0.2.9~150200.11.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch-javadoc", rpm:"jsch-javadoc~0.2.9~150200.11.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jgit", rpm:"eclipse-jgit~5.11.0~150200.3.15.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch", rpm:"jsch~0.2.9~150200.11.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch-demo", rpm:"jsch-demo~0.2.9~150200.11.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jsch-javadoc", rpm:"jsch-javadoc~0.2.9~150200.11.10.1", rls:"openSUSELeap15.5"))) {
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

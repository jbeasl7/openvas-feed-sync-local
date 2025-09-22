# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856965");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-12085", "CVE-2024-12086", "CVE-2024-12087", "CVE-2024-12088", "CVE-2024-12747");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 18:15:25 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-18 05:02:28 +0000 (Sat, 18 Jan 2025)");
  script_name("openSUSE: Security Advisory for rsync (SUSE-SU-2025:0165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0165-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KENPYAOT2J4QNMGUE25JMF4HOVO2GQTR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync'
  package(s) announced via the SUSE-SU-2025:0165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsync fixes the following issues:

  * CVE-2024-12085: leak of uninitialized stack data on the server leading to
      possible ASLR bypass. (bsc#1234101)

  * CVE-2024-12086: leak of a client machine's file contents through the
      processing of checksum data. (bsc#1234102)

  * CVE-2024-12087: arbitrary file overwrite possible on clients when symlink
      syncing is enabled. (bsc#1234103)

  * CVE-2024-12088: bypass of the --safe-links flag may allow the placement of
      unsafe symlinks in a client. (bsc#1234104)

  * CVE-2024-12747: Fixed a race condition in rsync handling symbolic links.
      (bsc#1235475)");

  script_tag(name:"affected", value:"'rsync' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"rsync-debuginfo", rpm:"rsync-debuginfo~3.2.3~150400.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debugsource", rpm:"rsync-debugsource~3.2.3~150400.3.17.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.2.3~150400.3.17.1", rls:"openSUSELeap15.4"))) {
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
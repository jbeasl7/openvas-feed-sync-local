# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833557");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32189", "CVE-2024-22231", "CVE-2024-22232");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:03 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for SUSE Manager 4.3.11 Release Notes (SUSE-SU-2024:0513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0513-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H5LEP6ZRG2ZFCNUFDHYNCCM72NJIL3PT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager 4.3.11 Release Notes'
  package(s) announced via the SUSE-SU-2024:0513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  release-notes-susemanager-proxy:

  * Update to SUSE Manager 4.3.11

  * Bugs mentioned: bsc#1213738, bsc#1216657, bsc#1216781, bsc#1217209,
      bsc#1217588 bsc#1218615, bsc#1218849, bsc#1219577, bsc#1219850

  ## Security update for SUSE Manager Server 4.3

  ### Description:

  This update fixes the following issues:

  release-notes-susemanager:

  * Update to SUSE Manager 4.3.11

  * Migrate from RHEL and its clones to SUSE Liberty Linux

  * Reboot required indication for non-SUSE distributions

  * SSH key rotation for enhanced security

  * Configure remote command execution

  * End of Debian 10 support

  * CVEs fixed: CVE-2023-32189, CVE-2024-22231, CVE-2024-22232

  * Bugs mentioned:
  bsc#1170848, bsc#1210911, bsc#1211254, bsc#1211560, bsc#1211912 bsc#1213079,
  bsc#1213507, bsc#1213738, bsc#1213981, bsc#1214077 bsc#1214791, bsc#1215166,
  bsc#1215514, bsc#1215769, bsc#1215810 bsc#1215813, bsc#1215982, bsc#1216114,
  bsc#1216394, bsc#1216437 bsc#1216550, bsc#1216657, bsc#1216753, bsc#1216781,
  bsc#1216988 bsc#1217069, bsc#1217209, bsc#1217588, bsc#1217784, bsc#1217869
  bsc#1218019, bsc#1218074, bsc#1218075, bsc#1218089, bsc#1218094 bsc#1218490,
  bsc#1218615, bsc#1218669, bsc#1218849, bsc#1219577 bsc#1219850, bsc#1218146

  ##");

  script_tag(name:"affected", value:"'SUSE Manager 4.3.11 Release Notes' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager-proxy", rpm:"release-notes-susemanager-proxy~4.3.11~150400.3.79.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager", rpm:"release-notes-susemanager~4.3.11~150400.3.100.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager-proxy", rpm:"release-notes-susemanager-proxy~4.3.11~150400.3.79.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager", rpm:"release-notes-susemanager~4.3.11~150400.3.100.1", rls:"openSUSELeap15.4"))) {
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

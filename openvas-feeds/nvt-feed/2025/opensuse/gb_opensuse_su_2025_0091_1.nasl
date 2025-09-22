# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0091.1");
  script_cve_id("CVE-2025-22868");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:00 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0091-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3WXUOMZG43G5AZBMH5HY5IUTZ2CLZL6M/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239264");
  script_xref(name:"URL", value:"https://github.com/restic/restic/releases/tag/v0.16.1");
  script_xref(name:"URL", value:"https://github.com/restic/restic/releases/tag/v0.17.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'restic' package(s) announced via the openSUSE-SU-2025:0091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for restic fixes the following issues:

- Fixed CVE-2025-22868: golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in golang.org/x/oauth2 (boo#1239264)

- Update to version 0.17.3

 - Fix #4971: Fix unusable mount on macOS Sonoma
 - Fix #5003: Fix metadata errors during backup of removable disks
 on Windows
 - Fix #5101: Do not retry load/list operation if SFTP connection
 is broken
 - Fix #5107: Fix metadata error on Windows for backups using VSS
 - Enh #5096: Allow prune --dry-run without lock

- Update to version 0.17.2

 - Fix #4004: Support container-level SAS/SAT tokens for Azure
 backend
 - Fix #5047: Resolve potential error during concurrent cache
 cleanup
 - Fix #5050: Return error if tag fails to lock repository
 - Fix #5057: Exclude irregular files from backups
 - Fix #5063: Correctly backup extended metadata when using VSS on
 Windows

- Update to version 0.17.1

 - Fix #2004: Correctly handle volume names in backup command on
 Windows
 - Fix #4945: Include missing backup error text with --json
 - Fix #4953: Correctly handle long paths on older Windows
 versions
 - Fix #4957: Fix delayed cancellation of certain commands
 - Fix #4958: Don't ignore metadata-setting errors during restore
 - Fix #4969: Correctly restore timestamp for files with resource
 forks on macOS
 - Fix #4975: Prevent backup --stdin-from-command from panicking
 - Fix #4980: Skip extended attribute processing on unsupported
 Windows volumes
 - Fix #5004: Fix spurious 'A Required Privilege Is Not Held by
 the Client' error
 - Fix #5005: Fix rare failures to retry locking a repository
 - Fix #5018: Improve HTTP/2 support for REST backend
 - Chg #4953: Also back up files with incomplete metadata
 - Enh #4795: Display progress bar for restore --verify
 - Enh #4934: Automatically clear removed snapshots from cache
 - Enh #4944: Print JSON-formatted errors during restore --json
 - Enh #4959: Return exit code 12 for 'bad password' errors
 - Enh #4970: Make timeout for stuck requests customizable

- Update to version 0.17.0

 - Fix #3600: Handle unreadable xattrs in folders above backup
 source
 - Fix #4209: Fix slow SFTP upload performance
 - Fix #4503: Correct hardlink handling in stats command
 - Fix #4568: Prevent forget --keep-tags <invalid> from deleting
 all snapshots
 - Fix #4615: Make find not sometimes ignore directories
 - Fix #4656: Properly report ID of newly added keys
 - Fix #4703: Shutdown cleanly when receiving SIGTERM
 - Fix #4709: Correct --no-lock handling of ls and tag commands
 - Fix #4760: Fix possible error on concurrent cache cleanup
 - Fix #4850: Handle UTF-16 password files in key command
 correctly
 - Fix #4902: Update snapshot summary on rewrite
 - Chg #956: Return exit code 10 and 11 for non-existing and
 locked repository
 - Chg #4540: Require at least ARMv6 for ARM binaries
 - Chg #4602: Deprecate legacy index format and s3legacy
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'restic' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"restic", rpm:"restic~0.17.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"restic-bash-completion", rpm:"restic-bash-completion~0.17.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"restic-zsh-completion", rpm:"restic-zsh-completion~0.17.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0110.1");
  script_tag(name:"creation_date", value:"2025-04-01 14:12:50 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0110-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0110-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/774IYQZ7MM6B6XG4OUL4ZECAW4Q5WNZN/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'restic' package(s) announced via the openSUSE-SU-2025:0110-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for restic fixes the following issues:

Update to 0.18.0

- Sec #5291: Mitigate attack on content-defined chunking algorithm
- Fix #1843: Correctly restore long filepaths' timestamp on old Windows
- Fix #2165: Ignore disappeared backup source files
- Fix #5153: Include root tree when searching using find --tree
- Fix #5169: Prevent Windows VSS event log 8194 warnings for backup with fs snapshot
- Fix #5212: Fix duplicate data handling in prune --max-unused
- Fix #5249: Fix creation of oversized index by repair index --read-all-packs
- Fix #5259: Fix rare crash in command output
- Chg #4938: Update dependencies and require Go 1.23 or newer
- Chg #5162: Promote feature flags
- Enh #1378: Add JSON support to check command
- Enh #2511: Support generating shell completions to stdout
- Enh #3697: Allow excluding online-only cloud files (e.g. OneDrive)
- Enh #4179: Add sort option to ls command
- Enh #4433: Change default sort order for find output
- Enh #4521: Add support for Microsoft Blob Storage access tiers
- Enh #4942: Add snapshot summary statistics to rewritten snapshots
- Enh #4948: Format exit errors as JSON when requested
- Enh #4983: Add SLSA provenance to GHCR container images
- Enh #5054: Enable compression for ZIP archives in dump command
- Enh #5081: Add retry mechanism for loading repository config
- Enh #5089: Allow including/excluding extended file attributes during restore
- Enh #5092: Show count of deleted files and directories during restore
- Enh #5109: Make small pack size configurable for prune
- Enh #5119: Add start and end timestamps to backup JSON output
- Enh #5131: Add DragonFlyBSD support
- Enh #5137: Make tag command print which snapshots were modified
- Enh #5141: Provide clear error message if AZURE_ACCOUNT_NAME is not set
- Enh #5173: Add experimental S3 cold storage support
- Enh #5174: Add xattr support for NetBSD 10+
- Enh #5251: Improve retry handling for flaky rclone backends
- Enh #52897: Make recover automatically rebuild index when needed");

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

  if(!isnull(res = isrpmvuln(pkg:"restic", rpm:"restic~0.18.0~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"restic-bash-completion", rpm:"restic-bash-completion~0.18.0~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"restic-zsh-completion", rpm:"restic-zsh-completion~0.18.0~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
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

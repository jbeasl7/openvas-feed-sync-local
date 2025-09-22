# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0153.1");
  script_cve_id("CVE-2024-53263");
  script_tag(name:"creation_date", value:"2025-05-13 14:23:20 +0000 (Tue, 13 May 2025)");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0153-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DUJEMV422T3LAPI4DRX6RNNLCCUYCIHN/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235876");
  script_xref(name:"URL", value:"https://github.com/git-lfs/git-lfs/releases/tag/v3.4.1");
  script_xref(name:"URL", value:"https://github.com/git-lfs/git-lfs/releases/tag/v3.6.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git-lfs' package(s) announced via the openSUSE-SU-2025:0153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git-lfs fixes the following issues:

Update to 3.6.1: (boo#1235876):

 This release introduces a security fix for all platforms, which
 has been assigned CVE-2024-53263.

 When requesting credentials from Git for a remote host, prior
 versions of Git LFS passed portions of the host's URL to the
 git-credential(1) command without checking for embedded
 line-ending control characters, and then sent any credentials
 received back from the Git credential helper to the remote host.
 By inserting URL-encoded control characters such as line feed
 (LF) or carriage return (CR) characters into the URL, an attacker
 might have been able to retrieve a user's Git credentials.
 Git LFS now prevents bare line feed (LF) characters from being
 included in the values sent to the git-credential(1) command, and
 also prevents bare carriage return (CR) characters from being
 included unless the credential.protectProtocol configuration
 option is set to a value equivalent to false.

 * Bugs

 - Reject bare line-ending control characters in Git credential
 requests (@chrisd8088)

update to version 3.6.0:

- [link moved to references]

update to 3.5.1:

 * Build release assets with Go 1.21 #5668 (@bk2204)
 * script/packagecloud: instantiate distro map properly #5662
 (@bk2204)
 * Install msgfmt on Windows in CI and release workflows
 #5666 (@chrisd8088)

update to version 3.4.1:

- [link moved to references]");

  script_tag(name:"affected", value:"'git-lfs' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"git-lfs", rpm:"git-lfs~3.6.1~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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

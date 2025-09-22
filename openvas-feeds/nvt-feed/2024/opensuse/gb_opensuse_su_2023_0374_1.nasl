# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833210");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-35934", "CVE-2023-46121");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-13 19:22:29 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:41:09 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for yt (openSUSE-SU-2023:0374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0374-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6MA5EHVFVH4HRBQQ5KZZ4YVOXJFQUG3W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yt'
  package(s) announced via the openSUSE-SU-2023:0374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yt-dlp fixes the following issues:

  - Update to release 2023.11.14

  * Security: [CVE-2023-46121] Patch Generic Extractor MITM Vulnerability
         via Arbitrary Proxy Injection

  * Disallow smuggling of arbitrary http_headers  extractors now
         only use specific headers

  - Make yt-dlp require the one pythonXX-yt-dlp that /usr/bin/yt-dlp was
       built with.

  - Rework Python build procedure [boo#1216467]

  - Enable Python library [boo#1216467]

  - Update to release 2023.10.13

  * youtube: fix some bug with --extractor-retries inf

  - Update to release 2023.10.07

  * yt: Fix heatmap extraction

  * yt: Raise a warning for Incomplete Data instead of an error

  - Update to release 2023.09.24

  * Extract subtitles from SMIL manifests

  * fb: Add dash manifest URL

  * crunchyroll: Remove initial state extraction

  * youtube: Add player_params extractor arg

  - remove suggests on brotlicffi - this is only for != cpython

  - Update to release 2023.07.06

  * Prevent Cookie leaks on HTTP redirect [boo#1213124] [CVE-2023-35934]

  * yt: Avoid false DRM detection

  * yt: Process post_live over 2 hours

  * yt: Support shorts-only playlists

  - Update to release 2023.06.22

  * youtube: add IOS to default clients used

  - Update to release 2023.06.21

  * Add option --compat-option playlist-match-filter

  * Add options --no-quiet, option --color, --netrc-cmd, --xff

  * Auto-select default format in -f-

  * Improve HTTP redirect handling

  * Support decoding multiple content encodings

  - Use python3.11 on Leap 15.5

  * python3.11 is the only python3   3.6 version would be shipped in Leap
         15.5

  - Update to release 2023.03.04

  * A bunch of extractor fixes

  - Update to release 2023.03.03

  * youtube: Construct dash formats with range query

  * yt: Detect and break on looping comments

  * yt: Extract channel view_count when /about tab is passed

  - Update to release 2023.02.17

  * Merge youtube-dl: Upto commit/2dd6c6e (Feb 17 2023)

  * Fix --concat-playlist

  * Imply --no-progress when --print

  * Improve default subtitle language selection

  * Make title completely non-fatal

  * Sanitize formats before sorting

  * [hls] Allow extractors to provide AES key

  * [extractor/generic] Avoid catastrophic backtracking in KVS regex

  * [jsinterp] Support if statements

  * [plugins] Fix zip search paths

  * [utils] Don't use  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'yt' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python311-yt-dlp", rpm:"python311-yt-dlp~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp", rpm:"yt-dlp~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-bash-completion", rpm:"yt-dlp-bash-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-fish-completion", rpm:"yt-dlp-fish-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-zsh-completion", rpm:"yt-dlp-zsh-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-yt-dlp", rpm:"python311-yt-dlp~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp", rpm:"yt-dlp~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-bash-completion", rpm:"yt-dlp-bash-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-fish-completion", rpm:"yt-dlp-fish-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yt-dlp-zsh-completion", rpm:"yt-dlp-zsh-completion~2023.11.14~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
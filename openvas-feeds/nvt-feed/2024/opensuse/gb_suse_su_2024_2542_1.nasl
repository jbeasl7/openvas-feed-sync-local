# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856317");
  script_cve_id("CVE-2024-22020", "CVE-2024-27980", "CVE-2024-36138");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:30 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2542-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2542-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242542-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227560");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018991.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18' package(s) announced via the SUSE-SU-2024:2542-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:

Update to 18.20.4:

- CVE-2024-36138: Fixed CVE-2024-27980 fix bypass (bsc#1227560)
- CVE-2024-22020: Fixed a bypass of network import restriction via data URL (bsc#1227554)

Changes in 18.20.3:

- This release fixes a regression introduced in Node.js 18.19.0 where http.server.close() was incorrectly closing idle connections.
 deps:
 - acorn updated to 8.11.3.
 - acorn-walk updated to 8.3.2.
 - ada updated to 2.7.8.
 - c-ares updated to 1.28.1.
 - corepack updated to 0.28.0.
 - nghttp2 updated to 1.61.0.
 - ngtcp2 updated to 1.3.0.
 - npm updated to 10.7.0. Includes a fix from npm@10.5.1 to limit the number of open connections npm/cli#7324.
 - simdutf updated to 5.2.4.

Changes in 18.20.2:

- CVE-2024-27980: Fixed command injection via args parameter of child_process.spawn without shell option enabled on Windows (bsc#1222665)");

  script_tag(name:"affected", value:"'nodejs18' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.20.4~150400.9.24.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.20.4~150400.9.24.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.20.4~150400.9.24.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.20.4~150400.9.24.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.20.4~150400.9.24.2", rls:"openSUSELeap15.5"))) {
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

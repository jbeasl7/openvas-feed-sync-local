# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856630");
  script_cve_id("CVE-2024-38355", "CVE-2024-38998", "CVE-2024-38999", "CVE-2024-39338", "CVE-2024-4067", "CVE-2024-4068", "CVE-2024-43788", "CVE-2024-48948", "CVE-2024-48949", "CVE-2024-9014");
  script_tag(name:"creation_date", value:"2024-10-30 05:00:48 +0000 (Wed, 30 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 14:07:04 +0000 (Tue, 15 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3771-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3771-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243771-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231684");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019689.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4' package(s) announced via the SUSE-SU-2024:3771-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pgadmin4 fixes the following issues:

- CVE-2024-38355: Fixed socket.io: unhandled 'error' event (bsc#1226967)
- CVE-2024-38998: Fixed requirejs: prototype pollution via function config (bsc#1227248)
- CVE-2024-38999: Fixed requirejs: prototype pollution via function s.contexts._.configure (bsc#1227252)
- CVE-2024-39338: Fixed axios: server-side request forgery due to requests for path relative URLs being processed as protocol relative URLs in axios (bsc#1229423)
- CVE-2024-4067: Fixed micromatch: vulnerable to Regular Expression Denial of Service (ReDoS) (bsc#1224366)
- CVE-2024-4068: Fixed braces: fails to limit the number of characters it can handle, which could lead to Memory Exhaustion (bsc#1224295)
- CVE-2024-43788: Fixed webpack: DOM clobbering gadget in AutoPublicPathRuntimeModule could lead to XSS (bsc#1229861)
- CVE-2024-48948: Fixed elliptic: ECDSA signature verification error due to leading zero may reject legitimate transactions in elliptic (bsc#1231684)
- CVE-2024-48949: Fixed elliptic: Missing Validation in Elliptic's EDDSA Signature Verification (bsc#1231564)
- CVE-2024-9014: Fixed OAuth2 issue that could lead to information leak (bsc#1230928)");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-cloud", rpm:"pgadmin4-cloud~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-desktop", rpm:"pgadmin4-desktop~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-web-uwsgi", rpm:"pgadmin4-web-uwsgi~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-pgadmin", rpm:"system-user-pgadmin~8.5~150600.3.6.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0592.1");
  script_cve_id("CVE-2024-45337", "CVE-2025-22868", "CVE-2025-22869", "CVE-2025-22870", "CVE-2025-27144", "CVE-2025-30204", "CVE-2025-58181", "CVE-2026-22772", "CVE-2026-24137");
  script_tag(name:"creation_date", value:"2026-02-23 04:42:47 +0000 (Mon, 23 Feb 2026)");
  script_version("2026-02-23T06:01:22+0000");
  script_tag(name:"last_modification", value:"2026-02-23 06:01:22 +0000 (Mon, 23 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0592-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260592-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257138");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024365.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vexctl' package(s) announced via the SUSE-SU-2026:0592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vexctl fixes the following issues:

- Update to version 0.4.1+git78.f951e3a:
- CVE-2025-22868: Unexpected memory consumption during token parsing in golang.org/x/oauth2. (bsc#1239186)
- CVE-2024-45337: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto. (bsc#1234486)
- CVE-2025-27144: Go JOSE's Parsing Vulnerable to Denial of Service. (bsc#1237611)
- CVE-2025-22870: proxy bypass using IPv6 zone IDs. (bsc#1238683)
- CVE-2025-22869: Denial of Service in the Key Exchange of golang.org/x/crypto/ssh. (bsc#1239323)
- CVE-2025-30204: jwt-go allows excessive memory allocation during header parsing. (bsc#1240444)
- CVE-2025-58181: invalidated number of mechanisms can cause unbounded memory consumption. (bsc#1253802)
- CVE-2026-22772: MetaIssuer URL validation bypass can trigger SSRF to arbitrary internal services. (bsc#1256535)
- CVE-2026-24137: legacy TUF client allows for arbitrary file writes with target cache path traversal. (bsc#1257138)");

  script_tag(name:"affected", value:"'vexctl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"vexctl", rpm:"vexctl~0.4.1+git78.f951e3a~150000.1.11.1", rls:"openSUSELeap15.6"))) {
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

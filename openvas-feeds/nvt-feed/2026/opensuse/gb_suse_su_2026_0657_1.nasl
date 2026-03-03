# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0657.1");
  script_cve_id("CVE-2025-32049", "CVE-2026-2369", "CVE-2026-2443", "CVE-2026-2708");
  script_tag(name:"creation_date", value:"2026-03-02 04:36:59 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-03 14:15:43 +0000 (Thu, 03 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0657-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0657-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260657-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258508");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024453.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup2' package(s) announced via the SUSE-SU-2026:0657-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup2 fixes the following issues:

- CVE-2025-32049: denial of Service attack to websocket server (bsc#1240751).
- CVE-2026-2369: buffer overread due to integer underflow when handling zero-length resources (bsc#1258120).
- CVE-2026-2443: out-of-bounds read when processing specially crafted HTTP Range headers can lead to heap information
 disclosure to remote attackers (bsc#1258170).
- CVE-2026-2708: HTTP request smuggling via duplicate Content-Length headers (bsc#1258508).");

  script_tag(name:"affected", value:"'libsoup2' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-32bit", rpm:"libsoup-2_4-1-32bit~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2-devel", rpm:"libsoup2-devel~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2-devel-32bit", rpm:"libsoup2-devel-32bit~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2-lang", rpm:"libsoup2-lang~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.74.3~150600.4.27.1", rls:"openSUSELeap15.6"))) {
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

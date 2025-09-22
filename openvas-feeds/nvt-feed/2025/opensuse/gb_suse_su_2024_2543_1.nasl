# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2543.1");
  script_cve_id("CVE-2024-22018", "CVE-2024-22020", "CVE-2024-27980", "CVE-2024-36137", "CVE-2024-36138", "CVE-2024-37372");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2543-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2543-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242543-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227563");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018990.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the SUSE-SU-2024:2543-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs20 fixes the following issues:

Update to 20.15.1:

- CVE-2024-36138: Fixed CVE-2024-27980 fix bypass (bsc#1227560)
- CVE-2024-22020: Fixed a bypass of network import restriction via data URL (bsc#1227554)
- CVE-2024-22018: Fixed fs.lstat bypasses permission model (bsc#1227562)
- CVE-2024-36137: Fixed fs.fchown/fchmod bypasses permission model (bsc#1227561)
- CVE-2024-37372: Fixed Permission model improperly processes UNC paths (bsc#1227563)

Changes in 20.15.0:

- test_runner: support test plans
- inspector: introduce the --inspect-wait flag
- zlib: expose zlib.crc32()
- cli: allow running wasm in limited vmem with --disable-wasm-trap-handler

Changes in 20.14.0

- src,permission: throw async errors on async APIs
- test_runner: support forced exit

Changes in 20.13.1:

- buffer: improve base64 and base64url performance
- crypto: deprecate implicitly shortened GCM tags
- events,doc: mark CustomEvent as stable
- fs: add stacktrace to fs/promises
- report: add --report-exclude-network option
- src: add uv_get_available_memory to report and process
- stream: support typed arrays
- util: support array of formats in util.styleText
- v8: implement v8.queryObjects() for memory leak regression testing
- watch: mark as stable");

  script_tag(name:"affected", value:"'nodejs20' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"corepack20", rpm:"corepack20~20.15.1~150500.11.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.15.1~150500.11.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.15.1~150500.11.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.15.1~150500.11.12.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm20", rpm:"npm20~20.15.1~150500.11.12.2", rls:"openSUSELeap15.5"))) {
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

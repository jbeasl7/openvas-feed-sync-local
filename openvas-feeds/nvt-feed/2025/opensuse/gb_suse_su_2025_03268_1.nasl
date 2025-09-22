# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03268.1");
  script_cve_id("CVE-2025-10148", "CVE-2025-9086");
  script_tag(name:"creation_date", value:"2025-09-22 04:06:48 +0000 (Mon, 22 Sep 2025)");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03268-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03268-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503268-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249367");
  script_xref(name:"URL", value:"https://curl.se/ch/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041769.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2025:03268-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

Security issues fixed:

- CVE-2025-9086: bug in patch comparison logic when processing cookies can lead to out-of-bounds read in heap buffer
 (bsc#1249191).
- CVE-2025-10148: predictable websocket mask can lead to proxy cache poisoning by malicious server (bsc#1249348).

Other issues fixed:

- Fix the --ftp-pasv option in curl v8.14.1 (bsc#1246197).
 * tool_getparam: fix --ftp-pasv [5f805ee]

- Update to version 8.14.1 (jsc#PED-13055, jsc#PED-13056).
 * TLS: add CURLOPT_SSL_SIGNATURE_ALGORITHMS and --sigalgs.
 * websocket: add option to disable auto-pong reply.
 * huge number of bugfixes.

 Please see [link moved to references] for full changelogs.");

  script_tag(name:"affected", value:"'curl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"brotli", rpm:"brotli~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotli-devel", rpm:"libbrotli-devel~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlicommon1", rpm:"libbrotlicommon1~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlicommon1-32bit", rpm:"libbrotlicommon1-32bit~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlidec1", rpm:"libbrotlidec1~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlidec1-32bit", rpm:"libbrotlidec1-32bit~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlienc1", rpm:"libbrotlienc1~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbrotlienc1-32bit", rpm:"libbrotlienc1-32bit~1.0.7~150200.3.5.1", rls:"openSUSELeap15.6"))) {
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

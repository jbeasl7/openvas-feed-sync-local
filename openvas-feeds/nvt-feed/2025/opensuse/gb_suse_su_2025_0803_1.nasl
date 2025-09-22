# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0803.1");
  script_cve_id("CVE-2025-22870");
  script_tag(name:"creation_date", value:"2025-03-10 04:05:40 +0000 (Mon, 10 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0803-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0803-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250803-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238572");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020485.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.23' package(s) announced via the SUSE-SU-2025:0803-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.23 fixes the following issues:

 - CVE-2025-22870: golang.org/x/net/proxy, golang.org/x/net/http/httpproxy: Fixed proxy bypass using IPv6 zone IDs (bsc#1238572)

 Other fixes:

 - Updated go version to go1.23.7 (bsc#1229122):
 * go#71985 go#71984 bsc#1238572 security: fix CVE-2025-22870 net/http, x/net/proxy, x/net/http/httpproxy: proxy bypass using IPv6 zone IDs
 * go#71727 runtime: usleep computes wrong tv_nsec on s390x
 * go#71839 runtime: recover added in range-over-func loop body doesn't stop panic propagation / segfaults printing error
 * go#71848 os: spurious SIGCHILD on running child process
 * go#71875 reflect: Value.Seq panicking on functional iterator methods
 * go#71915 reflect: Value.Seq iteration value types not matching the type of given int types
 * go#71962 runtime/cgo: does not build with -Wdeclaration-after-statement");

  script_tag(name:"affected", value:"'go1.23' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.23", rpm:"go1.23~1.23.7~150000.1.24.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-doc", rpm:"go1.23-doc~1.23.7~150000.1.24.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.23-race", rpm:"go1.23-race~1.23.7~150000.1.24.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0874.1");
  script_cve_id("CVE-2025-25184", "CVE-2025-27111", "CVE-2025-27610");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:00 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0874-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0874-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250874-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239298");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020518.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rack' package(s) announced via the SUSE-SU-2025:0874-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rack fixes the following issues:

- CVE-2025-25184: Fixed escape sequence injection vulnerability in rack leading to possible log injection (bsc#1237141)
- CVE-2025-27111: Fixed escape sequence injection vulnerability in rack leading to possible log injection (bsc#1238607)
- CVE-2025-27610: Fixed improper sanitization of user-supplied paths (bsc#1239298)");

  script_tag(name:"affected", value:"'rubygem-rack' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack", rpm:"ruby2.5-rubygem-rack~2.0.8~150000.3.26.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack-doc", rpm:"ruby2.5-rubygem-rack-doc~2.0.8~150000.3.26.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack-testsuite", rpm:"ruby2.5-rubygem-rack-testsuite~2.0.8~150000.3.26.1", rls:"openSUSELeap15.6"))) {
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

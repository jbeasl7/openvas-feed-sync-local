# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856844");
  script_cve_id("CVE-2024-21538");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:35 +0000 (Fri, 13 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4301-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244301-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233856");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019991.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18' package(s) announced via the SUSE-SU-2024:4301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:

- CVE-2024-21538: Fixed regular expression denial of service in cross-spawn dependency (bsc#1233856)

Other fixes:
- Update to 18.20.5
 * esm: mark import attributes and JSON module as stable
 * deps:
 + upgrade npm to 10.8.2
 + update simdutf to 5.6.0
 + update brotli to 1.1.0
 + update ada to 2.8.0
 + update acorn to 8.13.0
 + update acorn-walk to 8.3.4
 + update c-ares to 1.29.0");

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

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.20.5~150400.9.30.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.20.5~150400.9.30.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.20.5~150400.9.30.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.20.5~150400.9.30.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.20.5~150400.9.30.1", rls:"openSUSELeap15.5"))) {
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

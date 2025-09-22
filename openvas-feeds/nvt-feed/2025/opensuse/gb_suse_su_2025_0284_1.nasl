# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857013");
  script_cve_id("CVE-2025-22150", "CVE-2025-23083", "CVE-2025-23085");
  script_tag(name:"creation_date", value:"2025-01-30 05:00:16 +0000 (Thu, 30 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0284-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250284-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236258");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020235.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the SUSE-SU-2025:0284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs22 fixes the following issues:

Update to 22.13.1:

- CVE-2025-23083: Fixed worker permission bypass via InternalWorker leak in diagnostics (bsc#1236251)
- CVE-2025-23085: Fixed HTTP2 memory leak on premature close and ERR_PROTO (bsc#1236250)
- CVE-2025-22150: Fixed insufficiently random values used when defining the boundary for a multipart/form-data request in undici (bsc#1236258)");

  script_tag(name:"affected", value:"'nodejs22' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"corepack22", rpm:"corepack22~22.13.1~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.13.1~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-devel", rpm:"nodejs22-devel~22.13.1~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-docs", rpm:"nodejs22-docs~22.13.1~150600.13.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm22", rpm:"npm22~22.13.1~150600.13.6.1", rls:"openSUSELeap15.6"))) {
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

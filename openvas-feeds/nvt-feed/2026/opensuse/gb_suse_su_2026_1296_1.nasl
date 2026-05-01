# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1296.1");
  script_cve_id("CVE-2025-13462", "CVE-2026-3644", "CVE-2026-4224", "CVE-2026-4519");
  script_tag(name:"creation_date", value:"2026-04-15 04:58:26 +0000 (Wed, 15 Apr 2026)");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1296-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1296-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261296-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260026");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045432.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2026:1296-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

- CVE-2025-13462: incorrect parsing of TarInfo when GNU long name and type AREGTYPE are combined can lead to
 misinterpretation of tar archives (bsc#1259611).
- CVE-2026-3644: incomplete control character validation in http.cookies can lead to input validation bypass
 (bsc#1259734).
- CVE-2026-4224: parsing XML with deeply nested DTD content models can lead to C stack overflow (bsc#1259735).
- CVE-2026-4519: failure to sanitize leading dashes in URLs in the `webbrowser.open()` API can lead to web browser
 command line option injection (bsc#1260026).");

  script_tag(name:"affected", value:"'python39' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit", rpm:"libpython3_9-1_0-32bit~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit", rpm:"python39-32bit~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit", rpm:"python39-base-32bit~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc", rpm:"python39-doc~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc-devhelp", rpm:"python39-doc-devhelp~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite", rpm:"python39-testsuite~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.25~150300.4.99.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03019.1");
  script_cve_id("CVE-2025-8713", "CVE-2025-8714", "CVE-2025-8715");
  script_tag(name:"creation_date", value:"2025-09-01 04:12:42 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03019-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03019-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503019-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248122");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041420.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql14' package(s) announced via the SUSE-SU-2025:03019-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql14 fixes the following issues:

Upgrade to 14.19:

- CVE-2025-8713: optimizer statistics can expose sampled data within a view, partition, or child table (bsc#1248120).
- CVE-2025-8714: untrusted data inclusion in `pg_dump` lets superuser of origin server execute arbitrary code in psql
 client (bsc#1248122).
- CVE-2025-8715: improper neutralization of newlines in `pg_dump` allows execution of arbitrary code in psql client and
 in restore target server (bsc#1248119).");

  script_tag(name:"affected", value:"'postgresql14' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-devel", rpm:"postgresql14-llvmjit-devel~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.19~150600.16.20.1", rls:"openSUSELeap15.6"))) {
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

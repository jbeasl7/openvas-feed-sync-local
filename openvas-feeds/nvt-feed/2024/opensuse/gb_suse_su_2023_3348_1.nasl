# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833290");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-39417");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-18 17:58:49 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:57:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for postgresql15 (SUSE-SU-2023:3348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3348-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7PUNRDQUDTP3JTWMMA4LPJ4UET75CUQ4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql15'
  package(s) announced via the SUSE-SU-2023:3348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql15 fixes the following issues:

  * Update to 14.9

  * CVE-2023-39417: Fixed potential SQL injection for trusted extensions.
      (bsc#1214059)

  ##");

  script_tag(name:"affected", value:"'postgresql15' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel-debuginfo", rpm:"postgresql14-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debugsource", rpm:"postgresql14-debugsource~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl-debuginfo", rpm:"postgresql14-plperl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython-debuginfo", rpm:"postgresql14-plpython-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib-debuginfo", rpm:"postgresql14-contrib-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-devel", rpm:"postgresql14-llvmjit-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debuginfo", rpm:"postgresql14-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-debuginfo", rpm:"postgresql14-server-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel-debuginfo", rpm:"postgresql14-server-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-debuginfo", rpm:"postgresql14-llvmjit-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl-debuginfo", rpm:"postgresql14-pltcl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel-debuginfo", rpm:"postgresql14-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debugsource", rpm:"postgresql14-debugsource~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl-debuginfo", rpm:"postgresql14-plperl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython-debuginfo", rpm:"postgresql14-plpython-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib-debuginfo", rpm:"postgresql14-contrib-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-devel", rpm:"postgresql14-llvmjit-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debuginfo", rpm:"postgresql14-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-debuginfo", rpm:"postgresql14-server-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel-debuginfo", rpm:"postgresql14-server-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-debuginfo", rpm:"postgresql14-llvmjit-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl-debuginfo", rpm:"postgresql14-pltcl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.9~150200.5.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel-debuginfo", rpm:"postgresql14-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debugsource", rpm:"postgresql14-debugsource~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl-debuginfo", rpm:"postgresql14-plperl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython-debuginfo", rpm:"postgresql14-plpython-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib-debuginfo", rpm:"postgresql14-contrib-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-devel", rpm:"postgresql14-llvmjit-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debuginfo", rpm:"postgresql14-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-debuginfo", rpm:"postgresql14-server-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel-debuginfo", rpm:"postgresql14-server-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-debuginfo", rpm:"postgresql14-llvmjit-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl-debuginfo", rpm:"postgresql14-pltcl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel-debuginfo", rpm:"postgresql14-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib", rpm:"postgresql14-contrib~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14", rpm:"postgresql14~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debugsource", rpm:"postgresql14-debugsource~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl-debuginfo", rpm:"postgresql14-plperl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plperl", rpm:"postgresql14-plperl~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl", rpm:"postgresql14-pltcl~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython-debuginfo", rpm:"postgresql14-plpython-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-contrib-debuginfo", rpm:"postgresql14-contrib-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-devel", rpm:"postgresql14-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-devel", rpm:"postgresql14-llvmjit-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel", rpm:"postgresql14-server-devel~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-debuginfo", rpm:"postgresql14-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-debuginfo", rpm:"postgresql14-server-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-plpython", rpm:"postgresql14-plpython~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server-devel-debuginfo", rpm:"postgresql14-server-devel-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-debuginfo", rpm:"postgresql14-llvmjit-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-pltcl-debuginfo", rpm:"postgresql14-pltcl-debuginfo~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-server", rpm:"postgresql14-server~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-docs", rpm:"postgresql14-docs~14.9~150200.5.29.1", rls:"openSUSELeap15.5"))) {
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

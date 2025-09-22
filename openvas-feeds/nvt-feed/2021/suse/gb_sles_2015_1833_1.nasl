# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1833.1");
  script_cve_id("CVE-2015-5276");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1833-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151833-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949000");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001648.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc48' package(s) announced via the SUSE-SU-2015:1833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for GCC 4.8 provides the following fixes:

- Fix C++11 std::random_device short read issue that could lead to predictable
 randomness. (CVE-2015-5276, bsc#945842)
- Fix linker segmentation fault when building SLOF on ppc64le. (bsc#949000)
- Fix no_instrument_function attribute handling on PPC64 with -mprofile-kernel. (bsc#947791)
- Fix internal compiler error with aarch64 target using PCH and builtin functions. (bsc#947772)
- Fix libffi issues on aarch64. (bsc#948168)");

  script_tag(name:"affected", value:"'gcc48' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"cpp48", rpm:"cpp48~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-32bit", rpm:"gcc48-32bit~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48", rpm:"gcc48~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-c++", rpm:"gcc48-c++~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-info", rpm:"gcc48-info~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc48-locale", rpm:"gcc48-locale~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan0-32bit", rpm:"libasan0-32bit~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasan0", rpm:"libasan0~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++48-devel-32bit", rpm:"libstdc++48-devel-32bit~4.8.5~24.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++48-devel", rpm:"libstdc++48-devel~4.8.5~24.1", rls:"SLES12.0"))) {
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

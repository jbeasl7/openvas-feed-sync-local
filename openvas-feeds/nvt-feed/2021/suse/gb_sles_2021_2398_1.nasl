# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2398.1");
  script_cve_id("CVE-2021-34558");
  script_tag(name:"creation_date", value:"2021-07-20 02:22:03 +0000 (Tue, 20 Jul 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 13:49:09 +0000 (Fri, 30 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2398-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2398-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212398-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.15' package(s) announced via the SUSE-SU-2021:2398-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.15 fixes the following issues:

go1.15.14 (released 2021-07-12) includes a security fix to the
 crypto/tls package, as well as bug fixes to the linker, and the net
 package. CVE-2021-34558 Refs bsc#1175132 go1.15 release tracking
 * bsc#1188229 go#47143 CVE-2021-34558
 * go#47144 security: fix CVE-2021-34558
 * go#47012 net: LookupMX behaviour broken
 * go#46994 net: TestCVE202133195 fails if /etc/resolv.conf specifies
 ndots larger than 3
 * go#46768 syscall: TestGroupCleanupUserNamespace test failure on Fedora
 * go#46684 x/build/cmd/release: linux-armv6l release tests aren't passing
 * go#46656 runtime: deeply nested struct initialized with non-zero values

Fix extraneous trailing percent character %endif% in spec file.");

  script_tag(name:"affected", value:"'go1.15' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.14~1.36.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.14~1.36.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-race", rpm:"go1.15-race~1.15.14~1.36.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.14~1.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.14~1.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-race", rpm:"go1.15-race~1.15.14~1.36.1", rls:"SLES15.0SP3"))) {
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

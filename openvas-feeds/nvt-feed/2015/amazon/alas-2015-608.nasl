# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120598");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_tag(name:"creation_date", value:"2015-11-08 11:11:00 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-608)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-608");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-608.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss-util, nss, jss' package(s) announced via the ALAS-2015-608 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support cross-platform development of security-enabled client and server applications. Netscape Portable Runtime (NSPR) provides platform independence for non-GUI operating system facilities.

A use-after-poison flaw and a heap-based buffer overflow flaw were found in the way NSS parsed certain ASN.1 structures. An attacker could use these flaws to cause NSS to crash or execute arbitrary code with the permissions of the user running an application compiled against the NSS library. (CVE-2015-7181, CVE-2015-7182)

A heap-based buffer overflow was found in NSPR. An attacker could use this flaw to cause NSPR to crash or execute arbitrary code with the permissions of the user running an application compiled against the NSPR library. (CVE-2015-7183)

Note: Applications using NSPR's PL_ARENA_ALLOCATE, PR_ARENA_ALLOCATE, PL_ARENA_GROW, or PR_ARENA_GROW macros need to be rebuild against the fixed nspr packages to completely resolve the CVE-2015-7183 issue. This erratum includes nss and nss-utils packages rebuilt against the fixed nspr version.");

  script_tag(name:"affected", value:"'nspr, nss-util, nss, jss' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"jss", rpm:"jss~4.2.6~35.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jss-debuginfo", rpm:"jss-debuginfo~4.2.6~35.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jss-javadoc", rpm:"jss-javadoc~4.2.6~35.17.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.8~2.35.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.10.8~2.35.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.8~2.35.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.19.1~7.74.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.19.1~4.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-debuginfo", rpm:"nss-util-debuginfo~3.19.1~4.47.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.19.1~4.47.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120017");
  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1995", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2064", "CVE-2013-2066");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:02 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-452");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-452.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libX11, libXcursor, libXfixes, libXi, libXrandr, libXrender, libXres, libXt, libXv, libXvMC, libXxf86dga, libXxf86vm, libdmx, xorg-x11-proto-devel' package(s) announced via the ALAS-2014-452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer overflow flaws, leading to heap-based buffer overflows, were found in the way various X11 client libraries handled certain protocol data. An attacker able to submit invalid protocol data to an X11 server via a malicious X11 client could use either of these flaws to potentially escalate their privileges on the system. (CVE-2013-1981, CVE-2013-1982, CVE-2013-1983, CVE-2013-1984, CVE-2013-1985, CVE-2013-1986, CVE-2013-1987, CVE-2013-1988, CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-2003, CVE-2013-2062, CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer out-of-bounds write flaws, were found in the way various X11 client libraries handled data returned from an X11 server. A malicious X11 server could possibly use this flaw to execute arbitrary code with the privileges of the user running an X11 client. (CVE-2013-1997, CVE-2013-1998, CVE-2013-1999, CVE-2013-2000, CVE-2013-2001, CVE-2013-2002, CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices() function of X.Org X11's libXi runtime library handled signed numbers. A malicious X11 server could possibly use this flaw to execute arbitrary code with the privileges of the user running an X11 client. (CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used uninitialized pointers. A malicious X11 server could possibly use this flaw to execute arbitrary code with the privileges of the user running an X11 client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11, the Core X11 protocol client library, processed certain user-specified files. A malicious X11 server could possibly use this flaw to crash an X11 client via a specially crafted file. (CVE-2013-2004)");

  script_tag(name:"affected", value:"'libX11, libXcursor, libXfixes, libXi, libXrandr, libXrender, libXres, libXt, libXv, libXvMC, libXxf86dga, libXxf86vm, libdmx, xorg-x11-proto-devel' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.6.0~2.2.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-common", rpm:"libX11-common~1.6.0~2.2.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debuginfo", rpm:"libX11-debuginfo~1.6.0~2.2.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.0~2.2.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXcursor", rpm:"libXcursor~1.1.14~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXcursor-debuginfo", rpm:"libXcursor-debuginfo~1.1.14~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXcursor-devel", rpm:"libXcursor-devel~1.1.14~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfixes", rpm:"libXfixes~5.0.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfixes-debuginfo", rpm:"libXfixes-debuginfo~5.0.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfixes-devel", rpm:"libXfixes-devel~5.0.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXi", rpm:"libXi~1.7.2~2.2.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXi-debuginfo", rpm:"libXi-debuginfo~1.7.2~2.2.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXi-devel", rpm:"libXi-devel~1.7.2~2.2.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrandr", rpm:"libXrandr~1.4.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrandr-debuginfo", rpm:"libXrandr-debuginfo~1.4.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrandr-devel", rpm:"libXrandr-devel~1.4.1~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrender", rpm:"libXrender~0.9.8~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrender-debuginfo", rpm:"libXrender-debuginfo~0.9.8~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrender-devel", rpm:"libXrender-devel~0.9.8~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXres", rpm:"libXres~1.0.7~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXres-debuginfo", rpm:"libXres-debuginfo~1.0.7~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXres-devel", rpm:"libXres-devel~1.0.7~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXt", rpm:"libXt~1.1.4~6.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXt-debuginfo", rpm:"libXt-debuginfo~1.1.4~6.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXt-devel", rpm:"libXt-devel~1.1.4~6.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXv", rpm:"libXv~1.0.9~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXv-debuginfo", rpm:"libXv-debuginfo~1.0.9~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXv-devel", rpm:"libXv-devel~1.0.9~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC", rpm:"libXvMC~1.0.8~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC-debuginfo", rpm:"libXvMC-debuginfo~1.0.8~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC-devel", rpm:"libXvMC-devel~1.0.8~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86dga", rpm:"libXxf86dga~1.1.4~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86dga-debuginfo", rpm:"libXxf86dga-debuginfo~1.1.4~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86dga-devel", rpm:"libXxf86dga-devel~1.1.4~2.1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86vm", rpm:"libXxf86vm~1.1.3~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86vm-debuginfo", rpm:"libXxf86vm-debuginfo~1.1.3~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXxf86vm-devel", rpm:"libXxf86vm-devel~1.1.3~2.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx", rpm:"libdmx~1.1.3~3.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx-debuginfo", rpm:"libdmx-debuginfo~1.1.3~3.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdmx-devel", rpm:"libdmx-devel~1.1.3~3.7.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-proto-devel", rpm:"xorg-x11-proto-devel~7.7~9.10.amzn1", rls:"AMAZON"))) {
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

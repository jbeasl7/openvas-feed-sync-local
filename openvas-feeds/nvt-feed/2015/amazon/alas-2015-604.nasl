# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120594");
  script_cve_id("CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2009-3546", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_tag(name:"creation_date", value:"2015-11-08 11:10:56 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-604)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-604");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-604.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwmf' package(s) announced via the ALAS-2015-604 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libwmf did not correctly process certain WMF (Windows Metafiles) with embedded BMP images. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly use this flaw to execute arbitrary code with the privileges of the user running the application. (CVE-2015-0848, CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF files. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly exploit this flaw to cause a crash or execute arbitrary code with the privileges of the user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF files. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly exploit this flaw to cause a crash. (CVE-2015-4695)

The gdPngReadData function in libgd 2.0.34 allows user-assisted attackers to cause a denial of service (CPU consumption) via a crafted PNG image with truncated data, which causes an infinite loop in the png_read_info function in libpng. (CVE-2007-2756)

Buffer overflow in the gdImageStringFTEx function in gdft.c in GD Graphics Library 2.0.33 and earlier allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a crafted string with a JIS encoded font. (CVE-2007-0455)

The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.x before 5.3.1, and the GD Graphics Library 2.x, does not properly verify a certain colorsTotal structure member, which might allow remote attackers to conduct buffer overflow or buffer over-read attacks via a crafted GD file, a different vulnerability than CVE-2009-3293. NOTE: some of these details are obtained from third party information. (CVE-2009-3546)

Integer overflow in gdImageCreateTrueColor function in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote attackers to have unspecified attack vectors and impact. (CVE-2007-3472)

The gdImageCreateXbm function in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote attackers to cause a denial of service (crash) via unspecified vectors involving a gdImageCreate failure. (CVE-2007-3473)");

  script_tag(name:"affected", value:"'libwmf' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~41.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-debuginfo", rpm:"libwmf-debuginfo~0.2.8.4~41.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-devel", rpm:"libwmf-devel~0.2.8.4~41.11.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-lite", rpm:"libwmf-lite~0.2.8.4~41.11.amzn1", rls:"AMAZON"))) {
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

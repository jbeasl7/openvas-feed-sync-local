# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120741");
  script_cve_id("CVE-2016-7446", "CVE-2016-7447", "CVE-2016-7448", "CVE-2016-7449");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:27 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 14:03:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-752");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-752.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick' package(s) announced via the ALAS-2016-752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A possible heap overflow was discovered in the EscapeParenthesis() function (CVE-2016-7447).

Various issues were found in the processing of SVG files in GraphicsMagick (CVE-2016-7446).

The TIFF reader had a bug pertaining to use of TIFFGetField() when a 'count' value is returned. The bug caused a heap read overflow (due to using strlcpy() to copy a possibly unterminated string) which could allow an untrusted file to crash the software (CVE-2016-7449).

The Utah RLE reader did not validate that header information was reasonable given the file size and so it could cause huge memory allocations and/or consume huge amounts of CPU, causing a denial of service (CVE-2016-7448)");

  script_tag(name:"affected", value:"'GraphicsMagick' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-c++", rpm:"GraphicsMagick-c++~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-c++-devel", rpm:"GraphicsMagick-c++-devel~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-doc", rpm:"GraphicsMagick-doc~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"GraphicsMagick-perl", rpm:"GraphicsMagick-perl~1.3.25~1.9.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120306");
  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:14 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-198");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-198.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa' package(s) announced via the ALAS-2013-198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds access flaw was found in Mesa. If an application using Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox does this), an attacker could cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2013-1872)

It was found that Mesa did not correctly validate messages from the X server. A malicious X server could cause an application using Mesa to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2013-1993)");

  script_tag(name:"affected", value:"'mesa' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"glx-utils", rpm:"glx-utils~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa", rpm:"mesa~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-debuginfo", rpm:"mesa-debuginfo~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGLU", rpm:"mesa-libGLU~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libGLU-devel", rpm:"mesa-libGLU-devel~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libOSMesa", rpm:"mesa-libOSMesa~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mesa-libOSMesa-devel", rpm:"mesa-libOSMesa-devel~9.0~0.8.15.amzn1", rls:"AMAZON"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120032");
  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:44 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-559");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-559.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the ALAS-2015-559 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A string reference count bug was found in cupsd, causing premature freeing of string objects. An attacker can submit a malicious print job that exploits this flaw to dismantle ACLs protecting privileged operations, allowing a replacement configuration file to be uploaded which in turn allows the attacker to run arbitrary code in the CUPS server (CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating engine. An attacker could use this flaw to bypass the default configuration settings that bind the CUPS scheduler to the 'localhost' or loopback interface. (CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found in the way cups handled compressed raster image files. An attacker could create a specially-crafted image file, which when passed via the cups Raster filter, could cause the cups filter to crash. (CVE-2014-9679)");

  script_tag(name:"affected", value:"'cups' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-php", rpm:"cups-php~1.4.2~67.21.amzn1", rls:"AMAZON"))) {
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

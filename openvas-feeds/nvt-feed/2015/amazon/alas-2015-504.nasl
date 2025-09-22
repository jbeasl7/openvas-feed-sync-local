# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120373");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141", "CVE-2014-9636");
  script_tag(name:"creation_date", value:"2015-09-08 11:24:56 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 20:50:00 +0000 (Wed, 05 Feb 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-504");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the ALAS-2015-504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was found in the way unzip uncompressed certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash or, possibly, execute arbitrary code when the archive was tested with unzip's '-t' option. (CVE-2014-9636)

A buffer overflow flaw was found in the way unzip computed the CRC32 checksum of certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash when the archive was tested with unzip's '-t' option. (CVE-2014-8139)

An integer underflow flaw, leading to a buffer overflow, was found in the way unzip uncompressed certain extra fields of a file. A specially crafted Zip archive could cause unzip to crash when the archive was tested with unzip's '-t' option. (CVE-2014-8140)

A buffer overflow flaw was found in the way unzip handled Zip64 files. A specially crafted Zip archive could possibly cause unzip to crash when the archive was uncompressed. (CVE-2014-8141)");

  script_tag(name:"affected", value:"'unzip' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.0~2.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unzip-debuginfo", rpm:"unzip-debuginfo~6.0~2.9.amzn1", rls:"AMAZON"))) {
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

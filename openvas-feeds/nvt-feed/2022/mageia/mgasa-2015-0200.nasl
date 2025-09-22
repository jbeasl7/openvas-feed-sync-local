# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0200");
  script_cve_id("CVE-2015-3622");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0200");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0200.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/04/30/6");
  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/9-Heap-overflow-invalid-read-in-Libtasn1-TFPA-0052015.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15804");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1' package(s) announced via the MGASA-2015-0200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libtasn1 packages fix security vulnerability:

A malformed certificate input could cause a heap overflow read in the DER
decoding functions of Libtasn1. The heap overflow happens in the function
_asn1_extract_der_octet() (CVE-2015-3622).");

  script_tag(name:"affected", value:"'libtasn1' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tasn1-devel", rpm:"lib64tasn1-devel~3.6~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tasn1_6", rpm:"lib64tasn1_6~3.6~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~3.6~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-devel", rpm:"libtasn1-devel~3.6~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1-tools", rpm:"libtasn1-tools~3.6~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtasn1_6", rpm:"libtasn1_6~3.6~1.2.mga4", rls:"MAGEIA4"))) {
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

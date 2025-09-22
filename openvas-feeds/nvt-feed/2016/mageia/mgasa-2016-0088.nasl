# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131249");
  script_cve_id("CVE-2016-0729");
  script_tag(name:"creation_date", value:"2016-03-03 12:39:18 +0000 (Thu, 03 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-08 14:34:39 +0000 (Fri, 08 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0088");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0088.html");
  script_xref(name:"URL", value:"http://xerces.apache.org/xerces-c/secadv/CVE-2016-0729.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17820");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c' package(s) announced via the MGASA-2016-0088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xerces-c packages fix security vulnerability:

The Xerces-C XML parser mishandles certain kinds of malformed input documents,
resulting in buffer overlows during processing and error reporting. The
overflows can manifest as a segmentation fault or as memory corruption during
a parse operation. The bugs allow for a denial of service attack in many
applications by an unauthenticated attacker, and could conceivably result in
remote code execution (CVE-2016-0729).");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xerces-c-devel", rpm:"lib64xerces-c-devel~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xerces-c3.1", rpm:"lib64xerces-c3.1~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxerces-c-devel", rpm:"libxerces-c-devel~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxerces-c3.1", rpm:"libxerces-c3.1~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-c", rpm:"xerces-c~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~3.1.2~1.1.mga5", rls:"MAGEIA5"))) {
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

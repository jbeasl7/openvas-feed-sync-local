# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0019");
  script_cve_id("CVE-2019-12211", "CVE-2019-12213");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 20:31:09 +0000 (Mon, 20 May 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0019");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0019.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25967");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/56P2TDRB2FEJEWDRIAOPGEDF7L2VNA7B/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/PUWVVP67FYM4GMWD7TPQ7C7JPPRUZHYE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeimage' package(s) announced via the MGASA-2020-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

When FreeImage 3.18.0 reads a tiff file, it will be handed to the Load
function of the PluginTIFF.cpp file, but a memcpy occurs in which the
destination address and the size of the copied data are not considered,
resulting in a heap overflow. (CVE-2019-12211)

When FreeImage 3.18.0 reads a special TIFF file, the TIFFReadDirectory
function in PluginTIFF.cpp always returns 1, leading to stack exhaustion.
(CVE-2019-12213)");

  script_tag(name:"affected", value:"'freeimage' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"freeimage", rpm:"freeimage~3.18.0~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeimage-devel", rpm:"lib64freeimage-devel~3.18.0~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeimage3", rpm:"lib64freeimage3~3.18.0~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeimage-devel", rpm:"libfreeimage-devel~3.18.0~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeimage3", rpm:"libfreeimage3~3.18.0~2.mga7", rls:"MAGEIA7"))) {
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

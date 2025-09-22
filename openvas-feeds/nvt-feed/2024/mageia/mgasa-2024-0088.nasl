# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0088");
  script_cve_id("CVE-2022-28041");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 12:49:43 +0000 (Fri, 22 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0088");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0088.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30366");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OHTD76NDEN77KCPI3XGGK2VVSA25WWEG/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SEQGDVH43YW7AG7TRU2CTU5TMIYP27WP/");
  script_xref(name:"URL", value:"https://www.blender.org/download/lts/3-3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender, curaengine' package(s) announced via the MGASA-2024-0088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"stb_image.h v2.27 was discovered to contain an integer overflow via the
function stbi__jpeg_decode_block_prog_dc. This vulnerability allows
attackers to cause a Denial of Service (DoS) via unspecified vectors.
(CVE-2022-28041)");

  script_tag(name:"affected", value:"'blender, curaengine' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"blender", rpm:"blender~3.3.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curaengine", rpm:"curaengine~4.12.1~3.1.mga9", rls:"MAGEIA9"))) {
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

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0186");
  script_cve_id("CVE-2023-45681", "CVE-2023-47212");
  script_tag(name:"creation_date", value:"2024-05-22 04:11:38 +0000 (Wed, 22 May 2024)");
  script_version("2024-05-22T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-05-22 05:05:29 +0000 (Wed, 22 May 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-01 16:15:07 +0000 (Wed, 01 May 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0186");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0186.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33205");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2MHQQXX27ACLLYUQHWSL3DVCOGUK5ZA4/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stb' package(s) announced via the MGASA-2024-0186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"stb_vorbis is a single file MIT licensed library for processing ogg
vorbis files. A crafted file may trigger memory write past an allocated
heap buffer in `start_decoder`. The root cause is a potential integer
overflow in `sizeof(char*) * (f->comment_list_length)` which may make
`setup_malloc` allocate less memory than required. Since there is
another integer overflow an attacker may overflow it too to force
`setup_malloc` to return 0 and make the exploit more reliable. This
issue may lead to code execution.");

  script_tag(name:"affected", value:"'stb' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"stb", rpm:"stb~0~0.git20230129.4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb-devel", rpm:"stb-devel~0~0.git20230129.4.1.mga9", rls:"MAGEIA9"))) {
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

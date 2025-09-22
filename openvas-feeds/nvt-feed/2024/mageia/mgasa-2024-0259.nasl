# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0259");
  script_cve_id("CVE-2024-38439", "CVE-2024-38440", "CVE-2024-38441");
  script_tag(name:"creation_date", value:"2024-07-11 04:11:53 +0000 (Thu, 11 Jul 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 19:28:25 +0000 (Wed, 07 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0259");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0259.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33381");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UM3M423DHSUBERDIYCFHYY6XF2CAAMA2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netatalk' package(s) announced via the MGASA-2024-0259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Netatalk before 3.2.1 has an off-by-one error and resultant heap-based
buffer overflow because of setting ibuf[PASSWDLEN] to '\0' in FPLoginExt
in login in etc/uams/uams_pam.c. (CVE-2024-38439)
Netatalk before 3.2.1 has an off-by-one error, and resultant heap-based
buffer overflow and segmentation violation, because of incorrectly using
FPLoginExt in BN_bin2bn in etc/uams/uams_dhx_pam.c. The original issue
1097 report stated: 'The latest version of Netatalk (v3.2.0) contains a
security vulnerability. This vulnerability arises due to a lack of
validation for the length field after parsing user-provided data,
leading to an out-of-bounds heap write of one byte (\0). Under specific
configurations, this can result in reading metadata of the next heap
block, potentially causing a Denial of Service (DoS) under certain heap
layouts or with ASAN enabled. ... The vulnerability is located in the
FPLoginExt operation of Netatalk, in the BN_bin2bn function found in
/etc/uams/uams_dhx_pam.c ... if (!(bn = BN_bin2bn((unsigned char *)ibuf,
KEYSIZE, NULL))) ... threads ... [#0] Id 1, Name: 'afpd', stopped
0x7ffff4304e58 in ?? (), reason: SIGSEGV ... [#0] 0x7ffff4304e58 mov
BYTE PTR [r14+0x8], 0x0 ... mov rdx, QWORD PTR [rsp+0x18] ...
afp_login_ext(obj=<optimized out>, ibuf=0x62d000010424 '',
ibuflen=0xffffffffffff0015, rbuf=<optimized out>, rbuflen=<optimized
out>) ... afp_over_dsi(obj=0x5555556154c0 <obj>).'. (CVE-2024-38440)
Netatalk before 3.2.1 has an off-by-one error and resultant heap-based
buffer overflow because of setting ibuf[len] to '\0' in FPMapName in
afp_mapname in etc/afpd/directory.c. (CVE-2024-38441)");

  script_tag(name:"affected", value:"'netatalk' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64netatalk-devel", rpm:"lib64netatalk-devel~3.1.14~2.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64netatalk18", rpm:"lib64netatalk18~3.1.14~2.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetatalk-devel", rpm:"libnetatalk-devel~3.1.14~2.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetatalk18", rpm:"libnetatalk18~3.1.14~2.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netatalk", rpm:"netatalk~3.1.14~2.4.mga9", rls:"MAGEIA9"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1100");
  script_cve_id("CVE-2017-10686", "CVE-2017-11111", "CVE-2017-17811", "CVE-2017-17813", "CVE-2017-17814", "CVE-2017-17816", "CVE-2017-17817", "CVE-2017-17818", "CVE-2017-17820", "CVE-2018-19214", "CVE-2018-19215", "CVE-2018-8881", "CVE-2018-8882");
  script_tag(name:"creation_date", value:"2021-01-19 10:11:23 +0000 (Tue, 19 Jan 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 12:34:17 +0000 (Thu, 12 Apr 2018)");

  script_name("Huawei EulerOS: Security Advisory for nasm (EulerOS-SA-2021-1100)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1100");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1100");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'nasm' package(s) announced via the EulerOS-SA-2021-1100 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Netwide Assembler (NASM) 2.14rc15 has a heap-based buffer over-read in expand_mmac_params in asm/preproc.c for insufficient input.(CVE-2018-19214)

Netwide Assembler (NASM) 2.14rc16 has a heap-based buffer over-read in expand_mmac_params in asm/preproc.c for the special cases of the % and $ and ! characters.(CVE-2018-19215)

Netwide Assembler (NASM) 2.13.02rc2 has a heap-based buffer over-read in the function tokenize in asm/preproc.c, related to an unterminated string.(CVE-2018-8881)

Netwide Assembler (NASM) 2.13.02rc2 has a stack-based buffer under-read in the function ieee_shr in asm/float.c via a large shift value.(CVE-2018-8882)

In Netwide Assembler (NASM) 2.14rc0, there are multiple heap use after free vulnerabilities in the tool nasm. The related heap is allocated in the token() function and freed in the detoken() function (called by pp_getline()) - it is used again at multiple positions later that could cause multiple damages. For example, it causes a corrupted double-linked list in detoken(), a double free or corruption in delete_Token(), and an out-of-bounds write in detoken(). It has a high possibility to lead to a remote code execution attack.(CVE-2017-10686)

In Netwide Assembler (NASM) 2.14rc0, preproc.c allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted file.(CVE-2017-11111)

In Netwide Assembler (NASM) 2.14rc0, there is a heap-based buffer over-read that will cause a remote denial of service attack, related to a while loop in paste_tokens in asm/preproc.c.(CVE-2017-17818)

In Netwide Assembler (NASM) 2.14rc0, there is a heap-based buffer overflow that will cause a remote denial of service attack, related to a strcpy in paste_tokens in asm/preproc.c, a similar issue to CVE-2017-11111.(CVE-2017-17811)

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in the pp_list_one_macro function in asm/preproc.c that will cause a remote denial of service attack, related to mishandling of line-syntax errors.(CVE-2017-17813)

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in do_directive in asm/preproc.c that will cause a remote denial of service attack.(CVE-2017-17814)

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in pp_getline in asm/preproc.c that will cause a remote denial of service attack.(CVE-2017-17816)

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in pp_verror in asm/preproc.c that will cause a remote denial of service attack.(CVE-2017-17817)

In Netwide Assembler (NASM) 2.14rc0, there is a use-after-free in pp_list_one_macro in asm/preproc.c that will lead to a remote denial of service attack, related to mishandling of operand-type errors.(CVE-2017-17820)");

  script_tag(name:"affected", value:"'nasm' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"nasm", rpm:"nasm~2.10.07~7.h3", rls:"EULEROS-2.0SP3"))) {
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

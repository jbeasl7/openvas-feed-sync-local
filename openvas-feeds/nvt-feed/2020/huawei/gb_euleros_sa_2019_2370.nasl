# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2370");
  script_cve_id("CVE-2016-10217", "CVE-2016-10218", "CVE-2016-10219", "CVE-2016-10220", "CVE-2016-10317", "CVE-2017-11714", "CVE-2017-5951", "CVE-2017-7885", "CVE-2017-7975", "CVE-2017-9835", "CVE-2018-19478");
  script_tag(name:"creation_date", value:"2020-01-23 12:51:35 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-07 15:13:52 +0000 (Mon, 07 Aug 2017)");

  script_name("Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2019-2370)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2370");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2370");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2019-2370 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Artifex Ghostscript before 9.26, a carefully crafted PDF file can trigger an extremely long running computation when parsing the file.(CVE-2018-19478)

The gs_makewordimagedevice function in base/gsdevmem.c in Artifex Software, Inc. Ghostscript 9.20 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a crafted file that is mishandled in the PDF Transparency module.(CVE-2016-10220)

Artifex jbig2dec 0.13 has a heap-based buffer over-read leading to denial of service (application crash) or disclosure of sensitive information from process memory, because of an integer overflow in the jbig2_decode_symbol_dict function in jbig2_symbol_dict.c in libjbig2dec.a during operation on a crafted .jb2 file.(CVE-2017-7885)

Artifex jbig2dec 0.13, as used in Ghostscript, allows out-of-bounds writes because of an integer overflow in the jbig2_build_huffman_table function in jbig2_huffman.c during operations on a crafted JBIG2 file, leading to a denial of service (application crash) or possibly execution of arbitrary code.(CVE-2017-7975)

psi/ztoken.c in Artifex Ghostscript 9.21 mishandles references to the scanner state structure, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted PostScript document, related to an out-of-bounds read in the igc_reloc_struct_ptr function in psi/igc.c.(CVE-2017-11714)

The gs_alloc_ref_array function in psi/ialloc.c in Artifex Ghostscript 9.21 allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted PostScript document. This is related to a lack of an integer overflow check in base/gsalloc.c.(CVE-2017-9835)

The pdf14_pop_transparency_group function in base/gdevp14.c in the PDF Transparency module in Artifex Software, Inc. Ghostscript 9.20 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a crafted file.(CVE-2016-10218)

The fill_threshhold_buffer function in base/gxht_thresh.c in Artifex Software, Inc. Ghostscript 9.20 allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted PostScript document.(CVE-2016-10317)

The pdf14_open function in base/gdevp14.c in Artifex Software, Inc. Ghostscript 9.20 allows remote attackers to cause a denial of service (use-after-free and application crash) via a crafted file that is mishandled in the color management module.(CVE-2016-10217)

The intersect function in base/gxfill.c in Artifex Software, Inc. Ghostscript 9.20 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted file.(CVE-2016-10219)

The mem_get_bits_rectangle function in base/gdevmem.c in Artifex Software, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~31.6.h15", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-cups", rpm:"ghostscript-cups~9.07~31.6.h15", rls:"EULEROS-2.0SP2"))) {
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

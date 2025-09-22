# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0279");
  script_cve_id("CVE-2022-21505", "CVE-2022-23825", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-36123", "CVE-2022-36879");
  script_tag(name:"creation_date", value:"2022-08-08 11:35:39 +0000 (Mon, 08 Aug 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-08 13:50:17 +0000 (Mon, 08 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0279)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0279");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0279.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30688");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.56");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.57");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.58");
  script_xref(name:"URL", value:"https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1037");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00702.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0279 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.58 and fixes at least
the following security issues:

Kernel lockdown bypass when UEFI secure boot is disabled / unavailable
and IMA appraisal is enabled (CVE-2022-21505).

Aliases in the branch predictor may cause some AMD processors to predict
the wrong branch type potentially leading to information disclosure
(CVE-2022-23825).

Mis-trained branch predictions for return instructions may allow arbitrary
speculative code execution under certain microarchitecture-dependent
conditions (CVE-2022-29900, RetBleed).

Intel microprocessor generations 6 to 8 are affected by a new Spectre
variant that is able to bypass their retpoline mitigation in the kernel
to leak arbitrary data. An attacker with unprivileged user access can
hijack return instructions to achieve arbitrary speculative code execution
under certain microarchitecture-dependent conditions (CVE-2022-29901).

The Linux kernel before 5.18.13 lacks a certain clear operation for the
block starting symbol (.bss). This allows Xen PV guest OS users to cause
a denial of service or gain privileges (CVE-2022-36123).

An issue was discovered in the Linux kernel through 5.18.14.
xfrm_expand_policies in net/xfrm/xfrm_policy.c can cause a refcount to be
dropped twice (CVE-2022-36879).

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.58-1.mga8", rpm:"kernel-linus-5.15.58-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.58-1.mga8", rpm:"kernel-linus-devel-5.15.58-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.58-1.mga8", rpm:"kernel-linus-source-5.15.58-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.58~1.mga8", rls:"MAGEIA8"))) {
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

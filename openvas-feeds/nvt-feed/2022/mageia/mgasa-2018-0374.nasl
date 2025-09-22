# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0374");
  script_cve_id("CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 13:53:37 +0000 (Thu, 25 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0374");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0374.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23544");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23560");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.66");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.67");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.68");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.69");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2018-0374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on the upstream 4.14.69 and adds additional
fixes for the L1TF and Spectre security issues. It also fixes at least
the following security issues:

Memory leak in the irda_bind function in net/irda/af_irda.c and later in
drivers/staging/irda/net/af_irda.c in the Linux kernel before 4.17 allows
local users to cause a denial of service (memory consumption) by repeatedly
binding an AF_IRDA socket (CVE-2018-6554).

The irda_setsockopt function in net/irda/af_irda.c and later in
drivers/staging/irda/net/af_irda.c in the Linux kernel before 4.17 allows
local users to cause a denial of service (ias_object use-after-free and
system crash) or possibly have unspecified other impact via an AF_IRDA
socket (CVE-2018-6555).

Other fixes in this update:
* WireGuard has been updated to 0.0.20180904
* all SPI_INTEL_SPI config options have been disable to prevent a potential
 bios corrupting bug (mga#23560)

For other changes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.14.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.14.69-1.mga6", rpm:"kernel-tmb-desktop-4.14.69-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.14.69-1.mga6", rpm:"kernel-tmb-desktop-devel-4.14.69-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.14.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.14.69~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.14.69-1.mga6", rpm:"kernel-tmb-source-4.14.69-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.14.69~1.mga6", rls:"MAGEIA6"))) {
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

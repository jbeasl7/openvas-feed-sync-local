# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1663.1");
  script_cve_id("CVE-2018-1000199", "CVE-2019-14615", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16994", "CVE-2019-19036", "CVE-2019-19045", "CVE-2019-19054", "CVE-2019-19318", "CVE-2019-19319", "CVE-2019-19447", "CVE-2019-19462", "CVE-2019-19768", "CVE-2019-19770", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20095", "CVE-2019-20096", "CVE-2019-20810", "CVE-2019-20812", "CVE-2019-3701", "CVE-2019-9455", "CVE-2019-9458", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-10711", "CVE-2020-10720", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11669", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12655", "CVE-2020-12656", "CVE-2020-12657", "CVE-2020-12769", "CVE-2020-13143", "CVE-2020-2732", "CVE-2020-7053", "CVE-2020-8428", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-8834", "CVE-2020-8992", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 15:01:42 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1663-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201663-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172458");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006971.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-0543: Fixed a side channel attack against special registers which could have resulted in leaking of read values to cores other than the one which called it.
 This attack is known as Special Register Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).
- CVE-2020-9383: Fixed an out-of-bounds read due to improper error condition check of FDC index (bsc#1165111).
- CVE-2020-8992: Fixed an issue which could have allowed attackers to cause a soft lockup via a crafted journal size (bsc#1164069).
- CVE-2020-8834: Fixed a stack corruption which could have lead to kernel panic (bsc#1168276).
- CVE-2020-8649: Fixed a use-after-free in the vgacon_invert_region function in drivers/video/console/vgacon.c (bsc#1162931).
- CVE-2020-8648: Fixed a use-after-free in the n_tty_receive_buf_common function in drivers/tty/n_tty.c (bsc#1162928).
- CVE-2020-8647: Fixed a use-after-free in the vc_do_resize function in drivers/tty/vt/vt.c (bsc#1162929).
- CVE-2020-8428: Fixed a use-after-free which could have allowed local users to cause a denial of service (bsc#1162109).
- CVE-2020-7053: Fixed a use-after-free in the i915_ppgtt_close function in drivers/gpu/drm/i915/i915_gem_gtt.c (bsc#1160966).
- CVE-2020-2732: Fixed an issue affecting Intel CPUs where an L2 guest may trick the L0 hypervisor into accessing sensitive L1 resources (bsc#1163971).
- CVE-2020-13143: Fixed an out-of-bounds read in gadget_dev_desc_UDC_store in drivers/usb/gadget/configfs.c (bsc#1171982).
- CVE-2020-12769: Fixed an issue which could have allowed attackers to cause a panic via concurrent calls to dw_spi_irq and dw_spi_transfer_one (bsc#1171983).
- CVE-2020-12657: An a use-after-free in block/bfq-iosched.c (bsc#1171205).
- CVE-2020-12656: Fixed an improper handling of certain domain_release calls leadingch could have led to a memory leak (bsc#1171219).
- CVE-2020-12655: Fixed an issue which could have allowed attackers to trigger a sync of excessive duration via an XFS v5 image with crafted metadata (bsc#1171217).
- CVE-2020-12654: Fixed an issue in he wifi driver which could have allowed a remote AP to trigger a heap-based buffer overflow (bsc#1171202).
- CVE-2020-12653: Fixed an issue in the wifi driver which could have allowed local users to gain privileges or cause a denial of service (bsc#1171195).
- CVE-2020-12652: Fixed an issue which could have allowed local users to hold an incorrect lock during the ioctl operation and trigger a race condition (bsc#1171218).
- CVE-2020-12464: Fixed a use-after-free due to a transfer without a reference (bsc#1170901).
- CVE-2020-12114: Fixed a pivot_root race condition which could have allowed local users to cause a denial of service (panic) by corrupting a mountpoint reference counter (bsc#1171098).
- CVE-2020-11669: Fixed an issue ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.52.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.52.1", rls:"SLES15.0"))) {
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

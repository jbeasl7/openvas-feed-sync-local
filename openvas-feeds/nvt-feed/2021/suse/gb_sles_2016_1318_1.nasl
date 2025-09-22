# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1318.1");
  script_cve_id("CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-1779", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-15 16:17:38 +0000 (Fri, 15 Jan 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1318-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161318-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969126");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:1318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xen was updated to fix 46 security issues.

These security issues were fixed:
- CVE-2013-4527: Buffer overflow in hw/timer/hpet.c might have allowed remote attackers to execute arbitrary code via vectors related to the number of timers (bsc#964746).
- CVE-2013-4529: Buffer overflow in hw/pci/pcie_aer.c allowed remote attackers to cause a denial of service and possibly execute arbitrary code via a large log_num value in a savevm image (bsc#964929).
- CVE-2013-4530: Buffer overflow in hw/ssi/pl022.c allowed remote attackers to cause a denial of service or possibly execute arbitrary code via crafted tx_fifo_head and rx_fifo_head values in a savevm image (bsc#964950).
- CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load function in hw/arm/pxa2xx.c allowed remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted s->rx_level value in a savevm image (bsc#964644).
- CVE-2013-4534: Buffer overflow in hw/intc/openpic.c allowed remote attackers to cause a denial of service or possibly execute arbitrary code via vectors related to IRQDest elements (bsc#964452).
- CVE-2013-4537: The ssi_sd_transfer function in hw/sd/ssi-sd.c allowed remote attackers to execute arbitrary code via a crafted arglen value in a savevm image (bsc#962642).
- CVE-2013-4538: Multiple buffer overflows in the ssd0323_load function in hw/display/ssd0323.c allowed remote attackers to cause a denial of service (memory corruption) or possibly execute arbitrary code via crafted (1) cmd_len, (2) row, or (3) col values, (4) row_start and row_end values, or (5) col_star and col_end values in a savevm image (bsc#962335).
- CVE-2013-4539: Multiple buffer overflows in the tsc210x_load function in hw/input/tsc210x.c might have allowed remote attackers to execute arbitrary code via a crafted (1) precision, (2) nextprecision, (3) function, or (4) nextfunction value in a savevm image (bsc#962758).
- CVE-2014-0222: Integer overflow in the qcow_open function in block/qcow.c allowed remote attackers to cause a denial of service (crash) via a large L2 table in a QCOW version 1 image (bsc#964925).
- CVE-2014-3640: The sosendto function in slirp/udp.c allowed local users to cause a denial of service (NULL pointer dereference) by sending a udp packet with a value of 0 in the source port and address, which triggers access of an uninitialized socket (bsc#965112).
- CVE-2014-3689: The vmware-vga driver (hw/display/vmware_vga.c) allowed local guest users to write to qemu memory locations and gain privileges via unspecified parameters related to rectangle handling (bsc#962611).
- CVE-2014-7815: The set_pixel_format function in ui/vnc.c allowed remote attackers to cause a denial of service (crash) via a small bytes_per_pixel value (bsc#962627).
- CVE-2014-9718: The (1) BMDMA and (2) AHCI HBA interfaces in the IDE functionality had multiple interpretations of a function's return value, which allowed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_02_k3.12.55_52.42~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_02~22.19.1", rls:"SLES12.0"))) {
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

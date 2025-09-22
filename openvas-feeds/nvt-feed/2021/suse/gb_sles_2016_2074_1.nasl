# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2074.1");
  script_cve_id("CVE-2013-2015", "CVE-2013-7446", "CVE-2015-0272", "CVE-2015-3339", "CVE-2015-5307", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7509", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-7566", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-4486");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2074-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162074-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/861093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978822");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002207.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel was updated to receive various security and bug fixes.

The following security bugs were fixed:
- CVE-2016-4486: Fixed 4 byte information leak in net/core/rtnetlink.c (bsc#978822).
- CVE-2016-3134: The netfilter subsystem in the Linux kernel did not validate certain offset fields, which allowed local users to gain privileges or cause a denial of service (heap memory corruption) via an IPT_SO_SET_REPLACE setsockopt call (bnc#971126).
- CVE-2016-2847: fs/pipe.c in the Linux kernel did not limit the amount of unread data in pipes, which allowed local users to cause a denial of service (memory consumption) by creating many pipes with non-default sizes (bnc#970948).
- CVE-2016-2188: The iowarrior_probe function in drivers/usb/misc/iowarrior.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#970956).
- CVE-2016-3138: The acm_probe function in drivers/usb/class/cdc-acm.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a USB device without both a control and a data endpoint descriptor (bnc#970911).
- CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a USB device without both an interrupt-in and an interrupt-out endpoint descriptor, related to the cypress_generic_port_probe and cypress_open functions (bnc#970970).
- CVE-2016-3140: The digi_port_init function in drivers/usb/serial/digi_acceleport.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#970892).
- CVE-2016-2186: The powermate_probe function in drivers/input/misc/powermate.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#970958).
- CVE-2016-2185: The ati_remote2_probe function in drivers/input/misc/ati_remote2.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#971124).
- CVE-2016-3156: The IPv4 implementation in the Linux kernel mishandles destruction of device objects, which allowed guest OS users to cause a denial of service (host OS networking outage) by arranging for a large number of IP addresses (bnc#971360).
- CVE-2016-2184: The create_fixed_stream_quirk function in sound/usb/quirks.c in the snd-usb-audio driver in the Linux kernel allowed physically proximate attackers to cause a denial ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.7.40.1", rls:"SLES11.0SP2"))) {
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

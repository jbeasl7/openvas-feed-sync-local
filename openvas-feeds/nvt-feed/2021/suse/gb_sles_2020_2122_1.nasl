# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2122.1");
  script_cve_id("CVE-2019-16746", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-10781", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-14331", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-24 13:13:18 +0000 (Tue, 24 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2122-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202122-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174543");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-August/007224.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-14331: A buffer over write in vgacon_scroll was fixed (bnc#1174205).
- CVE-2020-10135: Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2 and earlier may have allowed an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key (bnc#1171988).
- CVE-2020-0305: In cdev_get of char_dev.c, there is a possible use-after-free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation (bnc#1174462).
- CVE-2019-20908: An issue was discovered in drivers/firmware/efi/efi.c where incorrect access permissions for the efivar_ssdt ACPI variable could be used by attackers to bypass lockdown or secure boot restrictions, aka CID-1957a85b0032 (bnc#1173567).
- CVE-2020-10781: zram sysfs resource consumption was fixed (bnc#1173074).
- CVE-2020-15780: An issue was discovered in drivers/acpi/acpi_configfs.c where injection of malicious ACPI tables via configfs could be used by attackers to bypass lockdown and secure boot restrictions, aka CID-75b0cea7bf30 (bnc#1173573).
- CVE-2020-15393: usbtest_disconnect in drivers/usb/misc/usbtest.c had a memory leak, aka CID-28ebeb8db770 (bnc#1173514).
- CVE-2020-12771: btree_gc_coalesce in drivers/md/bcache/btree.c had a deadlock if a coalescing operation fails (bnc#1171732).
- CVE-2019-16746: net/wireless/nl80211.c did not check the length of variable elements in a beacon head, leading to a buffer overflow (bnc#1152107).
- CVE-2020-12888: The VFIO PCI driver mishandled attempts to access disabled memory space (bnc#1171868).
- CVE-2020-10769: A buffer over-read flaw was found in crypto_authenc_extractkeys in crypto/authenc.c in the IPsec Cryptographic algorithm's module, authenc. When a payload longer than 4 bytes, and is not following 4-byte alignment boundary guidelines, it causes a buffer over-read threat, leading to a system crash. This flaw allowed a local attacker with user privileges to cause a denial of service (bnc#1173265).
- CVE-2020-10773: A kernel stack information leak on s390/s390x was fixed (bnc#1172999).
- CVE-2020-14416: A race condition in tty->disc_data handling in the slip and slcan line discipline could lead to a use-after-free, aka CID-0ace17d56824. This affects drivers/net/slip/slip.c and drivers/net/can/slcan.c (bnc#1162002).

The following non-security bugs were fixed:

- ACPI: GED: add support for _Exx / _Lxx handler methods (bsc#1111666).
- ACPI: GED: use correct trigger ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.29.1", rls:"SLES12.0SP5"))) {
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

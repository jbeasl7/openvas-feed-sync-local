# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0412");
  script_cve_id("CVE-2016-7042", "CVE-2016-7425", "CVE-2016-8630", "CVE-2016-8633");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-17 22:33:39 +0000 (Mon, 17 Oct 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0412");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0412.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19796");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.27");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.28");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.29");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.30");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.31");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.32");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2016-0412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on upstream 4.4.32 and fixes alteast the following
security issues:

The proc_keys_show function in security/keys/proc.c in the Linux kernel
through 4.8.2, when the GNU Compiler Collection (gcc) stack protector is
enabled, uses an incorrect buffer size for certain timeout data, which
allows local users to cause a denial of service (stack memory corruption
and panic) by reading the /proc/keys file (CVE-2016-7042).

The arcmsr_iop_message_xfer function in drivers/scsi/arcmsr/arcmsr_hba.c
in the Linux kernel through 4.8.2 does not restrict a certain length
field, which allows local users to gain privileges or cause a denial of
service (heap-based buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER
control code (CVE-2016-7425).

Null pointer dereference in kvm/emulate.c (CVE-2016-8630).

A buffer overflow vulnerability due to a lack of input filtering of
incoming fragmented datagrams was found in the IP-over-1394 driver
[firewire-net] in a fragment handling code in the Linux kernel. A
maliciously formed fragment with a respectively large datagram offset
would cause a memcpy() past the datagram buffer, which would cause a
system panic or possible arbitrary code execution. The flaw requires
[firewire-net] module to be loaded and is remotely exploitable from
connected firewire devices, but not over a local network (CVE-2016-8633).

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.32-1.mga5", rpm:"kernel-tmb-desktop-4.4.32-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.32-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.32-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.32~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.32-1.mga5", rpm:"kernel-tmb-source-4.4.32-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.32~1.mga5", rls:"MAGEIA5"))) {
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

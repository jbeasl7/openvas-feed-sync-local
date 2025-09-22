# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0114");
  script_cve_id("CVE-2024-2494");
  script_tag(name:"creation_date", value:"2024-04-09 04:13:31 +0000 (Tue, 09 Apr 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-21 14:15:10 +0000 (Thu, 21 Mar 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0114)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0114");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0114.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33047");
  script_xref(name:"URL", value:"https://lwn.net/Articles/967956/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the MGASA-2024-0114 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the RPC library APIs of libvirt. The RPC server
deserialization code allocates memory for arrays before the non-negative
length check is performed by the C API entry points. Passing a negative
length to the g_new0 function results in a crash due to the negative
length being treated as a huge positive number. This flaw allows a
local, unprivileged user to perform a denial of service attack by
causing the libvirt daemon to crash. (CVE-2024-2494)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64nss_libvirt2", rpm:"lib64nss_libvirt2~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt-devel", rpm:"lib64virt-devel~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64virt0", rpm:"lib64virt0~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss_libvirt2", rpm:"libnss_libvirt2~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-qemu", rpm:"libvirt-client-qemu~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-utils", rpm:"libvirt-utils~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt0", rpm:"libvirt0~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libvirt", rpm:"mingw32-libvirt~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libvirt", rpm:"mingw64-libvirt~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-libvirt", rpm:"wireshark-libvirt~9.6.0~1.1.mga9", rls:"MAGEIA9"))) {
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

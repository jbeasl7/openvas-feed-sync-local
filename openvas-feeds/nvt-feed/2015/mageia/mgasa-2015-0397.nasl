# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131096");
  script_cve_id("CVE-2015-5278", "CVE-2015-5279", "CVE-2015-7295");
  script_tag(name:"creation_date", value:"2015-10-15 03:54:52 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 17:48:59 +0000 (Fri, 31 Jan 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0397)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0397");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0397.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/09/18/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16761");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-October/169036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the MGASA-2015-0397 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qinghao Tang of QIHU 360 Inc. discovered an infinite loop issue in the
NE2000 NIC emulation. A privileged guest user could use this flaw to
mount a denial of service (QEMU process crash). (CVE-2015-5278)

Qinghao Tang of QIHU 360 Inc. discovered a heap buffer overflow flaw in
the NE2000 NIC emulation. A privileged guest user could use this flaw to
mount a denial of service (QEMU process crash), or potentially to execute
arbitrary code on the host with the privileges of the hosting QEMU
process. (CVE-2015-5279)

A flaw has been discovered in the QEMU emulator built with Virtual Network
Device(virtio-net) support. If the guest's virtio-net driver did not
support big or mergeable receive buffers, an issue could occur while
receiving large packets over the tuntap/ macvtap interfaces. An attacker
on the local network could use this flaw to disable the guest's
networking, the user could send a large number of jumbo frames to the
guest, which could exhaust all receive buffers, and lead to a denial of
service. (CVE-2015-7295)");

  script_tag(name:"affected", value:"'qemu' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.1.3~2.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.1.3~2.7.mga5", rls:"MAGEIA5"))) {
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

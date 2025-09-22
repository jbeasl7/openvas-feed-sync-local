# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0816.1");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151", "CVE-2013-4526", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4531", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0150", "CVE-2014-0182", "CVE-2014-2894");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 00:25:17 +0000 (Thu, 13 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0816-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0816-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140816-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'KVM' package(s) announced via the SUSE-SU-2014:0816-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues in KVM have been fixed. Some issues could have resulted in arbitrary code execution or crash of the kvm host.

 * virtio-net: buffer overflow in virtio_net_handle_mac() function
 (CVE-2014-0150)
 * Fixed out of bounds buffer accesses, guest triggerable via IDE SMART
 (CVE-2014-2894)
 *

 Fixed various virtio-net buffer overflows
(CVE-2013-4148,CVE-2013-4149,CVE-2013-4150,CVE-2013-4151)

 *

 Fixed ahci buffer overrun (CVE-2013-4526)

 * Fixed hpet buffer overrun (CVE-2013-4527)
 * Fixed a PCIE-AER buffer overrun (CVE-2013-4529)
 * Fixed a buffer overrun in pl022 (CVE-2013-4530)
 * Fixed a vmstate buffer overflow (CVE-2013-4531)
 * Fixed a pxa2xx buffer overrun (CVE-2013-4533)
 * Fixed a openpic buffer overrun (CVE-2013-4534)
 * Validate virtio num_sg mapping (CVE-2013-4535 / CVE-2013-4536)
 * Fixed ssi-sd buffer overrun (CVE-2013-4537)
 * Fixed ssd0323 buffer overrun (CVE-2013-4538)
 * Fixed tsc210x buffer overrun (CVE-2013-4539)
 * Fixed Zaurus buffer overrun (CVE-2013-4540)
 * Some USB sanity checking added (CVE-2013-4541)
 * Fixed virtio scsi buffer overrun (CVE-2013-4542)
 * Fixed another virtio buffer overrun (CVE-2013-6399)
 * Validate config_len on load in virtio (CVE-2014-0182)

Security Issue references:

 * CVE-2014-0150
 * CVE-2014-2894");

  script_tag(name:"affected", value:"'KVM' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~0.15.2", rls:"SLES11.0SP3"))) {
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

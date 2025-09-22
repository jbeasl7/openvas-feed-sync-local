# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702582");
  script_cve_id("CVE-2011-3131", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2582-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2582-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2582-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2582");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2582-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple denial of service vulnerabilities have been discovered in the Xen Hypervisor. One of the issue (CVE-2012-5513) could even lead to privilege escalation from guest to host.

Some of the recently published Xen Security Advisories (XSA 25 and 28) are not fixed by this update and should be fixed in a future release.

CVE-2011-3131 (XSA 5): DoS using I/OMMU faults from PCI-passthrough guest A VM that controls a PCI[E] device directly can cause it to issue DMA requests to invalid addresses. Although these requests are denied by the I/OMMU, the hypervisor needs to handle the interrupt and clear the error from the I/OMMU, and this can be used to live-lock a CPU and potentially hang the host.

CVE-2012-4535 (XSA 20): Timer overflow DoS vulnerability A guest which sets a VCPU with an inappropriate deadline can cause an infinite loop in Xen, blocking the affected physical CPU indefinitely.

CVE-2012-4537 (XSA 22): Memory mapping failure DoS vulnerability When set_p2m_entry fails, Xen's internal data structures (the p2m and m2p tables) can get out of sync. This failure can be triggered by unusual guest behaviour exhausting the memory reserved for the p2m table. If it happens, subsequent guest-invoked memory operations can cause Xen to fail an assertion and crash.

CVE-2012-4538 (XSA 23): Unhooking empty PAE entries DoS vulnerability The HVMOP_pagetable_dying hypercall does not correctly check the caller's pagetable state, leading to a hypervisor crash.

CVE-2012-4539 (XSA 24): Grant table hypercall infinite loop DoS vulnerability Due to inappropriate duplicate use of the same loop control variable, passing bad arguments to GNTTABOP_get_status_frames can cause an infinite loop in the compat hypercall handler.

CVE-2012-5510 (XSA 26): Grant table version switch list corruption vulnerability Downgrading the grant table version of a guest involves freeing its status pages. This freeing was incomplete - the page(s) are freed back to the allocator, but not removed from the domain's tracking list. This would cause list corruption, eventually leading to a hypervisor crash.

CVE-2012-5513 (XSA 29): XENMEM_exchange may overwrite hypervisor memory The handler for XENMEM_exchange accesses guest memory without range checking the guest provided addresses, thus allowing these accesses to include the hypervisor reserved range. A malicious guest administrator can cause Xen to crash. If the out of address space bounds access does not lead to a crash, a carefully crafted privilege escalation cannot be excluded, even though the guest doesn't itself control the values written.

CVE-2012-5514 (XSA 30): Broken error handling in guest_physmap_mark_populate_on_demand() guest_physmap_mark_populate_on_demand(), before carrying out its actual operation, checks that the subject GFNs are not in use. If that check fails, the code prints a message and bypasses ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.5", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.5", rls:"DEB6"))) {
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

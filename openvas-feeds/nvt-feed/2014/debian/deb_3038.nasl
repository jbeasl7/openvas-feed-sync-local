# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703038");
  script_cve_id("CVE-2014-0179", "CVE-2014-3633");
  script_tag(name:"creation_date", value:"2014-10-01 11:27:50 +0000 (Wed, 01 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3038-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3038-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3038-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3038");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-3038-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Libvirt, a virtualisation abstraction library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-0179

Richard Jones and Daniel P. Berrange found that libvirt passes the XML_PARSE_NOENT flag when parsing XML documents using the libxml2 library, in which case all XML entities in the parsed documents are expanded. A user able to force libvirtd to parse an XML document with an entity pointing to a special file that blocks on read access could use this flaw to cause libvirtd to hang indefinitely, resulting in a denial of service on the system.

CVE-2014-3633

Luyao Huang of Red Hat found that the qemu implementation of virDomainGetBlockIoTune computed an index into the array of disks for the live definition, then used it as the index into the array of disks for the persistent definition, which could result into an out-of-bounds read access in qemuDomainGetBlockIoTune().

A remote attacker able to establish a read-only connection to libvirtd could use this flaw to crash libvirtd or, potentially, leak memory from the libvirtd process.

For the stable distribution (wheezy), these problems have been fixed in version 0.9.12.3-1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.2.8-2.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-bin", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libvirt", ver:"0.9.12.3-1+deb7u1", rls:"DEB7"))) {
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

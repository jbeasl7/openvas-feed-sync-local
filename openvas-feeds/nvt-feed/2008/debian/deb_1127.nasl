# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57164");
  script_cve_id("CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1127");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1127");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1127");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal' package(s) announced via the DSA-1127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Ethereal network sniffer, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-3628

Ilja van Sprundel discovered that the FW-1 and MQ dissectors are vulnerable to format string attacks.

CVE-2006-3629

Ilja van Sprundel discovered that the MOUNT dissector is vulnerable to denial of service through memory exhaustion.

CVE-2006-3630

Ilja van Sprundel discovered off-by-one overflows in the NCP NMAS and NDPS dissectors.

CVE-2006-3631

Ilja van Sprundel discovered a buffer overflow in the NFS dissector.

CVE-2006-3632

Ilja van Sprundel discovered that the SSH dissector is vulnerable to denial of service through an infinite loop.

For the stable distribution (sarge) these problems have been fixed in version 0.10.10-2sarge6.

For the unstable distribution (sid) these problems have been fixed in version 0.99.2-1 of wireshark, the sniffer formerly known as ethereal.

We recommend that you upgrade your ethereal packages.");

  script_tag(name:"affected", value:"'ethereal' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge6", rls:"DEB3.1"))) {
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

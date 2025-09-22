# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703533");
  script_cve_id("CVE-2016-2074");
  script_tag(name:"creation_date", value:"2016-03-28 22:00:00 +0000 (Mon, 28 Mar 2016)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-07 15:43:10 +0000 (Thu, 07 Jul 2016)");

  script_name("Debian: Security Advisory (DSA-3533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3533-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3533-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3533");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openvswitch' package(s) announced via the DSA-3533-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kashyap Thimmaraju and Bhargava Shastry discovered a remotely triggerable buffer overflow vulnerability in openvswitch, a production quality, multilayer virtual switch implementation. Specially crafted MPLS packets could overflow the buffer reserved for MPLS labels in an OVS internal data structure. A remote attacker can take advantage of this flaw to cause a denial of service, or potentially, execution of arbitrary code.

For the stable distribution (jessie), this problem has been fixed in version 2.3.0+git20140819-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.3.0+git20140819-4.

We recommend that you upgrade your openvswitch packages.");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dbg", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-ipsec", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-pki", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-test", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-vtep", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-openvswitch", ver:"2.3.0+git20140819-3+deb8u1", rls:"DEB8"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842517");
  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5257", "CVE-2015-5283");
  script_tag(name:"creation_date", value:"2015-11-06 05:02:37 +0000 (Fri, 06 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2797-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2797-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2797-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not check if a new IPv6 MTU set
by a user space application was valid. A remote attacker could forge a
route advertisement with an invalid MTU that a user space daemon like
NetworkManager would honor and apply to the kernel, causing a denial of
service. (CVE-2015-0272)

It was discovered that in certain situations, a directory could be renamed
outside of a bind mounted location. An attacker could use this to escape
bind mount containment and gain access to sensitive information.
(CVE-2015-2925)

Moein Ghasemzadeh discovered that the USB WhiteHEAT serial driver contained
hardcoded attributes about the USB devices. An attacker could construct a
fake WhiteHEAT USB device that, when inserted, causes a denial of service
(system crash). (CVE-2015-5257)

It was discovered that the SCTP protocol implementation in the Linux kernel
performed an incorrect sequence of protocol-initialization steps. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2015-5283)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-generic", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-generic-lpae", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-lowlatency", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-powerpc-e500mc", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-powerpc-smp", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-powerpc64-emb", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-52-powerpc64-smp", ver:"3.16.0-52.71~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

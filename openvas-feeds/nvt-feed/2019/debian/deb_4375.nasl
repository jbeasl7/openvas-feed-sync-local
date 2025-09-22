# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704375");
  script_cve_id("CVE-2019-3813");
  script_tag(name:"creation_date", value:"2019-01-28 23:00:00 +0000 (Mon, 28 Jan 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-05 14:56:00 +0000 (Tue, 05 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-4375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4375-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4375-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4375");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/spice");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spice' package(s) announced via the DSA-4375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christophe Fergeau discovered an out-of-bounds read vulnerability in spice, a SPICE protocol client and server library, which might result in denial of service (spice server crash), or possibly, execution of arbitrary code.

For the stable distribution (stretch), this problem has been fixed in version 0.12.8-2.1+deb9u3.

We recommend that you upgrade your spice packages.

For the detailed security status of spice please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'spice' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libspice-server-dev", ver:"0.12.8-2.1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspice-server1", ver:"0.12.8-2.1+deb9u3", rls:"DEB9"))) {
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

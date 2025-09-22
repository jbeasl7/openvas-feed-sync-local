# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55487");
  script_cve_id("CVE-2005-2876");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-825-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-825-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-825");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'loop-aes-utils' package(s) announced via the DSA-825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Watson discovered a bug in mount as provided by util-linux and other packages such as loop-aes-utils that allows local users to bypass filesystem access restrictions by re-mounting it read-only.

The old stable distribution (woody) does not contain loop-aes-utils packages.

For the stable distribution (sarge) this problem has been fixed in version 2.12p-4sarge1.

For the unstable distribution (sid) this problem has been fixed in version 2.12p-9.

We recommend that you upgrade your loop-aes-utils package.");

  script_tag(name:"affected", value:"'loop-aes-utils' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"loop-aes-utils", ver:"2.12p-4sarge1", rls:"DEB3.1"))) {
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

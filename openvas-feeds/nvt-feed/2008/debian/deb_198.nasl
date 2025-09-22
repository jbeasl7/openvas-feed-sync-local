# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53442");
  script_cve_id("CVE-2002-1313");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-198");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-198");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-198");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nullmailer' package(s) announced via the DSA-198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A problem has been discovered in nullmailer, a simple relay-only mail transport agent for hosts that relay mail to a fixed set of smart relays. When a mail is to be delivered locally to a user that doesn't exist, nullmailer tries to deliver it, discovers a user unknown error and stops delivering. Unfortunately, it stops delivering entirely, not only this mail. Hence, it's very easy to craft a denial of service.

This problem has been fixed in version 1.00RC5-16.1woody2 for the current stable distribution (woody) and in version 1.00RC5-17 for the unstable distribution (sid). The old stable distribution (potato) does not contain a nullmailer package.

We recommend that you upgrade your nullmailer package.");

  script_tag(name:"affected", value:"'nullmailer' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"nullmailer", ver:"1.00RC5-16.1woody2", rls:"DEB3.0"))) {
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

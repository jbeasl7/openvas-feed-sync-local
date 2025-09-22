# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61371");
  script_cve_id("CVE-2008-1447", "CVE-2008-4099", "CVE-2008-4126");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2008-09-19 13:15:00 +0000 (Fri, 19 Sep 2008)");

  script_name("Debian: Security Advisory (DSA-1619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1619-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1619-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1619");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-dns' package(s) announced via the DSA-1619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple weaknesses have been identified in PyDNS, a DNS client implementation for the Python language. Dan Kaminsky identified a practical vector of DNS response spoofing and cache poisoning, exploiting the limited entropy in a DNS transaction ID and lack of UDP source port randomization in many DNS implementations. Scott Kitterman noted that python-dns is vulnerable to this predictability, as it randomizes neither its transaction ID nor its source port. Taken together, this lack of entropy leaves applications using python-dns to perform DNS queries highly susceptible to response forgery.

The Common Vulnerabilities and Exposures project identifies this class of weakness as CVE-2008-1447 and this specific instance in PyDNS as CVE-2008-4099.

For the stable distribution (etch), these problems have been fixed in version 2.3.0-5.2+etch1.

We recommend that you upgrade your python-dns package.");

  script_tag(name:"affected", value:"'python-dns' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"python-dns", ver:"2.3.0-5.2+etch1", rls:"DEB4"))) {
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

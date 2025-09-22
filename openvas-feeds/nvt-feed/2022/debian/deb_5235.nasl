# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705235");
  script_cve_id("CVE-2022-2795", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");
  script_tag(name:"creation_date", value:"2022-09-24 01:00:08 +0000 (Sat, 24 Sep 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 16:44:59 +0000 (Fri, 23 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5235-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5235-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5235");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-5235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server implementation.

CVE-2022-2795

Yehuda Afek, Anat Bremler-Barr and Shani Stajnrod discovered that a flaw in the resolver code can cause named to spend excessive amounts of time on processing large delegations, significantly degrade resolver performance and result in denial of service.

CVE-2022-3080

Maksym Odinintsev discovered that the resolver can crash when stale cache and stale answers are enabled with a zero stale-answer-timeout. A remote attacker can take advantage of this flaw to cause a denial of service (daemon crash) via specially crafted queries to the resolver.

CVE-2022-38177

It was discovered that the DNSSEC verification code for the ECDSA algorithm is susceptible to a memory leak flaw. A remote attacker can take advantage of this flaw to cause BIND to consume resources, resulting in a denial of service.

CVE-2022-38178

It was discovered that the DNSSEC verification code for the EdDSA algorithm is susceptible to a memory leak flaw. A remote attacker can take advantage of this flaw to cause BIND to consume resources, resulting in a denial of service.

For the stable distribution (bullseye), these problems have been fixed in version 1:9.16.33-1~deb11u1.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-dev", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-dnsutils", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-libs", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-utils", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9utils", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.16.33-1~deb11u1", rls:"DEB11"))) {
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

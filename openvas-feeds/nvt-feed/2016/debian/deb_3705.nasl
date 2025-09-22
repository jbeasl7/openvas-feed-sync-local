# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703705");
  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_tag(name:"creation_date", value:"2016-11-02 23:00:00 +0000 (Wed, 02 Nov 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-16 12:18:25 +0000 (Tue, 16 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3705-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3705-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3705");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-3705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in cURL, an URL transfer library:

CVE-2016-8615

It was discovered that a malicious HTTP server could inject new cookies for arbitrary domains into a cookie jar.

CVE-2016-8616

It was discovered that when re-using a connection, curl was doing case insensitive comparisons of user name and password with the existing connections.

CVE-2016-8617

It was discovered that on systems with 32-bit addresses in userspace (e.g. x86, ARM, x32), the output buffer size value calculated in the base64 encode function would wrap around if input size was at least 1GB of data, causing an undersized output buffer to be allocated.

CVE-2016-8618

It was discovered that the curl_maprintf() function could be tricked into doing a double-free due to an unsafe size_t multiplication on systems using 32 bit size_t variables.

CVE-2016-8619

It was discovered that the Kerberos implementation could be tricked into doing a double-free when reading one of the length fields from a socket.

CVE-2016-8620

It was discovered that the curl tool's globbing feature could write to invalid memory areas when parsing invalid ranges.

CVE-2016-8621

It was discovered that the function curl_getdate could read out of bounds when parsing invalid date strings.

CVE-2016-8622

It was discovered that the URL percent-encoding decode function would return a signed 32bit integer variable as length, even though it allocated a destination buffer larger than 2GB, which would lead to a out-of-bounds write.

CVE-2016-8623

It was discovered that libcurl could access an already-freed memory area due to concurrent access to shared cookies. This could lead to a denial of service or disclosure of sensitive information.

CVE-2016-8624

It was discovered that curl wouldn't parse the authority component of a URL correctly when the host name part ends with a '#' character, and could be tricked into connecting to a different host.

For the stable distribution (jessie), these problems have been fixed in version 7.38.0-4+deb8u5.

For the unstable distribution (sid), these problems have been fixed in version 7.51.0-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8"))) {
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

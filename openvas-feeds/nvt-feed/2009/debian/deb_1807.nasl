# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64109");
  script_cve_id("CVE-2009-0688");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1807-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1807-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1807-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1807");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl2, cyrus-sasl2-heimdal' package(s) announced via the DSA-1807-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Ralston discovered that the sasl_encode64() function of cyrus-sasl2, a free library implementing the Simple Authentication and Security Layer, suffers from a missing null termination in certain situations. This causes several buffer overflows in situations where cyrus-sasl2 itself requires the string to be null terminated which can lead to denial of service or arbitrary code execution.

Important notice (Quoting from US-CERT): While this patch will fix currently vulnerable code, it can cause non-vulnerable existing code to break. Here's a function prototype from include/saslutil.h to clarify my explanation:

/* base64 encode * in -- input data * inlen -- input data length * out -- output buffer (will be NUL terminated) * outmax -- max size of output buffer * result: * outlen -- gets actual length of output buffer (optional) * * Returns SASL_OK on success, SASL_BUFOVER if result won't fit */ LIBSASL_API int sasl_encode64(const char *in, unsigned inlen, char *out, unsigned outmax, unsigned *outlen),

Assume a scenario where calling code has been written in such a way that it calculates the exact size required for base64 encoding in advance, then allocates a buffer of that exact size, passing a pointer to the buffer into sasl_encode64() as *out. As long as this code does not anticipate that the buffer is NUL-terminated (does not call any string-handling functions like strlen(), for example) the code will work and it will not be vulnerable.

Once this patch is applied, that same code will break because sasl_encode64() will begin to return SASL_BUFOVER.

For the oldstable distribution (etch), this problem has been fixed in version 2.1.22.dfsg1-8+etch1 of cyrus-sasl2.

For the stable distribution (lenny), this problem has been fixed in version 2.1.22.dfsg1-23+lenny1 of cyrus-sasl2 and cyrus-sasl2-heimdal.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.1.23.dfsg1-1 of cyrus-sasl2 and cyrus-sasl2-heimdal.

We recommend that you upgrade your cyrus-sasl2/cyrus-sasl2-heimdal packages.");

  script_tag(name:"affected", value:"'cyrus-sasl2, cyrus-sasl2-heimdal' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-gssapi-mit", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-8+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-dbg", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-doc", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cyrus-sasl2-heimdal-dbg", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-2", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-dev", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-heimdal", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-gssapi-mit", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-ldap", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-otp", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl2-modules-sql", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl2-bin", ver:"2.1.22.dfsg1-23+lenny1", rls:"DEB5"))) {
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

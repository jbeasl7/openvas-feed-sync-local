# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53162");
  script_cve_id("CVE-2004-0079", "CVE-2004-0081");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2004-01-01 05:00:00 +0000 (Thu, 01 Jan 2004)");

  script_name("Debian: Security Advisory (DSA-465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-465");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-465");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-465");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl, openssl094, openssl095' package(s) announced via the DSA-465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in openssl, an implementation of the SSL protocol, using the Codenomicon TLS Test Tool. More information can be found in the following NISCC Vulnerability Advisory and this OpenSSL advisory. The Common Vulnerabilities and Exposures project identified the following vulnerabilities:

CAN-2004-0079

Null-pointer assignment in the do_change_cipher_spec() function. A remote attacker could perform a carefully crafted SSL/TLS handshake against a server that used the OpenSSL library in such a way as to cause OpenSSL to crash. Depending on the application this could lead to a denial of service.

CAN-2004-0081

A bug in older versions of OpenSSL 0.9.6 that can lead to a Denial of Service attack (infinite loop).

For the stable distribution (woody) these problems have been fixed in openssl version 0.9.6c-2.woody.6, openssl094 version 0.9.4-6.woody.4 and openssl095 version 0.9.5a-6.woody.5.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your openssl package.");

  script_tag(name:"affected", value:"'openssl, openssl094, openssl095' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl09", ver:"0.9.4-6.woody.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl095a", ver:"0.9.5a-6.woody.5", rls:"DEB3.0"))) {
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

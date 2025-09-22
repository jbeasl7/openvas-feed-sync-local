# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67209");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2010-0163");
  script_tag(name:"creation_date", value:"2010-04-06 19:31:38 +0000 (Tue, 06 Apr 2010)");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:21:52 +0000 (Wed, 14 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-2025-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2025-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2025-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2025");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird mail client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2408

Dan Kaminsky and Moxie Marlinspike discovered that icedove does not properly handle a '0' character in a domain name in the subject's Common Name (CN) field of an X.509 certificate (MFSA 2009-42).

CVE-2009-2404

Moxie Marlinspike reported a heap overflow vulnerability in the code that handles regular expressions in certificate names (MFSA 2009-43).

CVE-2009-2463

monarch2020 discovered an integer overflow in a base64 decoding function (MFSA 2010-07).

CVE-2009-3072

Josh Soref discovered a crash in the BinHex decoder (MFSA 2010-07).

CVE-2009-3075

Carsten Book reported a crash in the JavaScript engine (MFSA 2010-07).

CVE-2010-0163

Ludovic Hirlimann reported a crash indexing some messages with attachments, which could lead to the execution of arbitrary code (MFSA 2010-07).

For the stable distribution (lenny), these problems have been fixed in version 2.0.0.24-0lenny1.

Due to a problem with the archive system it is not possible to release all architectures. The missing architectures will be installed into the archive once they become available.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"2.0.0.24-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"2.0.0.24-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"2.0.0.24-0lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"2.0.0.24-0lenny1", rls:"DEB5"))) {
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

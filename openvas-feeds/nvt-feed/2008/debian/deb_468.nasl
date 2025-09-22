# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53165");
  script_cve_id("CVE-2004-0152", "CVE-2004-0153");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-468)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-468");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-468");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-468");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'emil' package(s) announced via the DSA-468 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar discovered a number of vulnerabilities in emil, a filter for converting Internet mail messages. The vulnerabilities fall into two categories:

CAN-2004-0152

Buffer overflows in (1) the encode_mime function, (2) the encode_uuencode function, (3) the decode_uuencode function. These bugs could allow a carefully crafted email message to cause the execution of arbitrary code supplied with the message when it is acted upon by emil.

CAN-2004-0153

Format string bugs in statements which print various error messages. The exploit potential of these bugs has not been established, and is probably configuration-dependent.

For the stable distribution (woody) these problems have been fixed in version 2.1.0-beta9-11woody1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your emil package.");

  script_tag(name:"affected", value:"'emil' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"emil", ver:"2.1.0-beta9-11woody1", rls:"DEB3.0"))) {
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

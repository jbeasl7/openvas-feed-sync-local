# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53485");
  script_cve_id("CVE-2004-0947", "CVE-2004-1027");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-652-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-652-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-652");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unarj' package(s) announced via the DSA-652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in unarj, a non-free ARJ unarchive utility. The Common Vulnerabilities and Exposures Project identifies the following vulnerabilities:

CAN-2004-0947

A buffer overflow has been discovered when handling long file names contained in an archive. An attacker could create a specially crafted archive which could cause unarj to crash or possibly execute arbitrary code when being extracted by a victim.

CAN-2004-1027

A directory traversal vulnerability has been found so that an attacker could create a specially crafted archive which would create files in the parent directory when being extracted by a victim. When used recursively, this vulnerability could be used to overwrite critical system files and programs.

For the stable distribution (woody) these problems have been fixed in version 2.43-3woody1.

For the unstable distribution (sid) these problems don't apply since unstable/non-free does not contain the unarj package.

We recommend that you upgrade your unarj package.");

  script_tag(name:"affected", value:"'unarj' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"unarj", ver:"2.43-3woody1", rls:"DEB3.0"))) {
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

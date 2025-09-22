# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53403");
  script_cve_id("CVE-2002-1425");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-141)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-141");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-141");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-141");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mpack' package(s) announced via the DSA-141 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eckehard Berns discovered a buffer overflow in the munpack program which is used for decoding (respectively) binary files in MIME (Multipurpose Internet Mail Extensions) format mail messages. If munpack is run on an appropriately malformed email (or news article) then it will crash, and perhaps can be made to run arbitrary code.

Herbert Xu reported a second vulnerability which affected malformed filenames that refer to files in upper directories like '../a'. The security impact is limited, though, because only a single leading '../' was accepted and only new files can be created (i.e. no files will be overwritten).

Both problems have been fixed in version 1.5-5potato2 for the old stable distribution (potato), in version 1.5-7woody2 for the current stable distribution (woody) and in version 1.5-9 for the unstable distribution (sid).

We recommend that you upgrade your mpack package immediately.");

  script_tag(name:"affected", value:"'mpack' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mpack", ver:"1.5-7woody2", rls:"DEB3.0"))) {
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

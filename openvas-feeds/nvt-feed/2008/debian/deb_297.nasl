# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53725");
  script_cve_id("CVE-2003-0033", "CVE-2003-0209");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-297)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-297");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-297");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-297");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'snort' package(s) announced via the DSA-297 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in Snort, a popular network intrusion detection system. Snort comes with modules and plugins that perform a variety of functions such as protocol analysis. The following issues have been identified:

Heap overflow in Snort 'stream4' preprocessor (VU#139129, CAN-2003-0209, Bugtraq Id 7178)

Researchers at CORE Security Technologies have discovered a remotely exploitable integer overflow that results in overwriting the heap in the 'stream4' preprocessor module. This module allows Snort to reassemble TCP packet fragments for further analysis. An attacker could insert arbitrary code that would be executed as the user running Snort, probably root.

Buffer overflow in Snort RPC preprocessor (VU#916785, CAN-2003-0033, Bugtraq Id 6963)

Researchers at Internet Security Systems X-Force have discovered a remotely exploitable buffer overflow in the Snort RPC preprocessor module. Snort incorrectly checks the lengths of what is being normalized against the current packet size. An attacker could exploit this to execute arbitrary code under the privileges of the Snort process, probably root.

For the stable distribution (woody) these problems have been fixed in version 1.8.4beta1-3.1.

The old stable distribution (potato) is not affected by these problems since it doesn't contain the problematic code.

For the unstable distribution (sid) these problems have been fixed in version 2.0.0-1.

We recommend that you upgrade your snort package immediately.

You are also advised to upgrade to the most recent version of Snort, since Snort, as any intrusion detection system, is rather useless if it is based on old and out-dated data and not kept up to date. Such installations would be unable to detect intrusions using modern methods. The current version of Snort is 2.0.0, while the version in the stable distribution (1.8) is quite old and the one in the old stable distribution is beyond hope.

Since Debian does not update arbitrary packages in stable releases, even Snort is not going to see updates other than to fix security problems, you are advised to upgrade to the most recent version from third party sources.");

  script_tag(name:"affected", value:"'snort' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"snort", ver:"1.8.4beta1-3.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snort-common", ver:"1.8.4beta1-3.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snort-doc", ver:"1.8.4beta1-3.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snort-mysql", ver:"1.8.4beta1-3.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snort-rules-default", ver:"1.8.4beta1-3.1", rls:"DEB3.0"))) {
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

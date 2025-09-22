# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842280");
  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2726", "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730", "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2015-07-16 04:20:46 +0000 (Thu, 16 Jul 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-07-07 17:59:20 +0000 (Tue, 07 Jul 2015)");

  script_name("Ubuntu: Security Advisory (USN-2656-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2656-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2656-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2656-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2656-1 fixed vulnerabilities in Firefox for Ubuntu 14.04 LTS and
later releases.

This update provides the corresponding update for Ubuntu 12.04 LTS.

Original advisory details:

 Karthikeyan Bhargavan discovered that NSS incorrectly handled state
 transitions for the TLS state machine. If a remote attacker were able to
 perform a machine-in-the-middle attack, this flaw could be exploited to skip
 the ServerKeyExchange message and remove the forward-secrecy property.
 (CVE-2015-2721)

 Looben Yan discovered 2 use-after-free issues when using XMLHttpRequest in
 some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit these to cause a
 denial of service via application crash, or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2015-2722,
 CVE-2015-2733)

 Bob Clary, Christian Holler, Bobby Holley, Andrew McCreight, Terrence
 Cole, Steve Fink, Mats Palmgren, Wes Kocher, Andreas Pehrson, Tooru
 Fujisawa, Andrew Sutherland, and Gary Kwong discovered multiple memory
 safety issues in Firefox. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit these to cause a
 denial of service via application crash, or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2015-2724,
 CVE-2015-2725, CVE-2015-2726)

 Armin Razmdjou discovered that opening hyperlinks with specific mouse
 and key combinations could allow a Chrome privileged URL to be opened
 without context restrictions being preserved. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially exploit
 this to bypass security restrictions. (CVE-2015-2727)

 Paul Bandha discovered a type confusion bug in the Indexed DB Manager. If
 a user were tricked in to opening a specially crafted website, an attacker
 could potentially exploit this to cause a denial of service via
 application crash or execute arbitrary code with the privileges of the
 user invoking Firefox. (CVE-2015-2728)

 Holger Fuhrmannek discovered an out-of-bounds read in Web Audio. If a
 user were tricked in to opening a specially crafted website, an attacker
 could potentially exploit this to obtain sensitive information.
 (CVE-2015-2729)

 Watson Ladd discovered that NSS incorrectly handled Elliptical Curve
 Cryptography (ECC) multiplication. A remote attacker could possibly use
 this issue to spoof ECDSA signatures. (CVE-2015-2730)

 A use-after-free was discovered when a Content Policy modifies the DOM to
 remove a DOM object. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit this to cause a
 denial of service via application crash or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2015-2731)

 Ronald Crane discovered multiple security vulnerabilities. If a user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"39.0+build5-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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

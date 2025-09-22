# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.296.1");
  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2782", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787", "CVE-2006-2788");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-296-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-296-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-296-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-296-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jonas Sicking discovered that under some circumstances persisted XUL
attributes are associated with the wrong URL. A malicious web site
could exploit this to execute arbitrary code with the privileges of
the user. (MFSA 2006-35, CVE-2006-2775)

Paul Nickerson discovered that content-defined setters on an object
prototype were getting called by privileged UI code. It was
demonstrated that this could be exploited to run arbitrary web script
with full user privileges (MFSA 2006-37, CVE-2006-2776). A similar
attack was discovered by moz_bug_r_a4 that leveraged SelectionObject
notifications that were called in privileged context. (MFSA 2006-43,
CVE-2006-2777)

Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
function. By tricking a user to visit a site with an SSL certificate
with specially crafted optional Certificate Authority name
arguments, this could potentially be exploited to execute arbitrary
code with the user's privileges. (MFSA 2006-38, CVE-2006-2778)

The Mozilla developer team discovered several bugs that lead to
crashes with memory corruption. These might be exploitable by
malicious web sites to execute arbitrary code with the privileges of
the user. (MFSA 2006-32, CVE-2006-2779, CVE-2006-2780, CVE-2006-2788)

Chuck McAuley reported that the fix for CVE-2006-1729 (file stealing
by changing input type) was not sufficient to prevent all variants of
exploitation. (MFSA 2006-41, CVE-2006-2782)

Masatoshi Kimura found a way to bypass web input sanitizers which
filter out JavaScript. By inserting 'Unicode Byte-order-Mark (BOM)'
characters into the HTML code (e. g. '<scr[BOM]ipt>'), these filters
might not recognize the tags anymore, however, Firefox would still
execute them since BOM markers are filtered out before processing the
page. (MFSA 2006-42, CVE-2006-2783)

Paul Nickerson noticed that the fix for CVE-2005-0752 (JavaScript
privilege escalation on the plugins page) was not sufficient to
prevent all variants of exploitation. (MFSA 2006-36, CVE-2006-2784)

Paul Nickerson demonstrated that if an attacker could convince a user
to right-click on a broken image and choose 'View Image' from the
context menu then he could get JavaScript to run on a site of the
attacker's choosing. This could be used to steal login cookies or
other confidential information from the target site. (MFSA 2006-34,
CVE-2006-2785)

Kazuho Oku discovered various ways to perform HTTP response smuggling
when used with certain proxy servers. Due to different interpretation
of nonstandard HTTP headers in Firefox and the proxy server, a
malicious web site can exploit this to send back two responses to one
request. The second response could be used to steal login cookies or
other sensitive data from another opened web site. (MFSA 2006-33,
CVE-2006-2786)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.4-0ubuntu6.06", rls:"UBUNTU6.06 LTS"))) {
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

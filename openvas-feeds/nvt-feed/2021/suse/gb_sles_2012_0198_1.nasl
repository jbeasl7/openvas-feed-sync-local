# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0198.1");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0198-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0198-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120198-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla XULrunner' package(s) announced via the SUSE-SU-2012:0198-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla XULrunner was updated to 1.9.2.26 security update,
fixing security issues and bugs. The following security bugs have been fixed:

 *

 MFSA 2012-01: Mozilla developers identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 In general these flaws cannot be exploited through email in the Thunderbird and SeaMonkey products because scripting is disabled, but are potentially a risk in browser or browser-like contexts in those products.
References

 *

 CVE-2012-0442: Jesse Ruderman and Bob Clary reported memory safety problems that were fixed in both Firefox 10 and Firefox 3.6.26.

 *

 MFSA 2012-02/CVE-2011-3670: For historical reasons Firefox has been generous in its interpretation of web addresses containing square brackets around the host. If this host was not a valid IPv6 literal address, Firefox attempted to interpret the host as a regular domain name.
Gregory Fleischer reported that requests made using IPv6 syntax using XMLHttpRequest objects through a proxy may generate errors depending on proxy configuration for IPv6.
The resulting error messages from the proxy may disclose sensitive data because Same-Origin Policy (SOP) will allow the XMLHttpRequest object to read these error messages,
allowing user privacy to be eroded. Firefox now enforces RFC 3986 IPv6 literal syntax and that may break links written using the non-standard Firefox-only forms that were previously accepted.

 This was fixed previously for Firefox 7.0,
Thunderbird 7.0, and SeaMonkey 2.4 but only fixed in Firefox 3.6.26 and Thunderbird 3.1.18 during 2012.

 *

 MFSA 2012-04/CVE-2011-3659: Security researcher regenrecht reported via TippingPoint's Zero Day Initiative that removed child nodes of nsDOMAttribute can be accessed under certain circumstances because of a premature notification of AttributeChildRemoved. This use-after-free of the child nodes could possibly allow for remote code execution.

 *

 MFSA 2012-07/CVE-2012-0444: Security researcher regenrecht reported via TippingPoint's Zero Day Initiative the possibility of memory corruption during the decoding of Ogg Vorbis files. This can cause a crash during decoding and has the potential for remote code execution.

 *

 MFSA 2012-08/CVE-2012-0449: Security researchers Nicolas Gregoire and Aki Helin independently reported that when processing a malformed embedded XSLT stylesheet,
Firefox can crash due to a memory corruption. While there is no evidence that this is directly exploitable, there is a possibility of remote code execution.");

  script_tag(name:"affected", value:"'Mozilla XULrunner' package(s) on SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.26~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.26~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.26~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations", rpm:"mozilla-xulrunner192-translations~1.9.2.26~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-x86", rpm:"mozilla-xulrunner192-x86~1.9.2.26~0.3.1", rls:"SLES11.0SP1"))) {
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

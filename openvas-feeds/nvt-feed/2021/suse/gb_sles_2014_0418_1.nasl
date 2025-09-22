# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0418.1");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1501", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-19 21:14:56 +0000 (Wed, 19 Mar 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0418-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140418-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2014:0418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox was updated to 24.4.0ESR release, fixing various security issues and bugs:

 *

 MFSA 2014-15: Mozilla developers and community identified identified and fixed several memory safety bugs in the browser engine used in Firefox and other Mozilla-based products. Some of these bugs showed evidence of memory corruption under certain circumstances, and we presume that with enough effort at least some of these could be exploited to run arbitrary code.

 *

 Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij,
Jesse Ruderman, Dan Gohman, and Christoph Diehl reported memory safety problems and crashes that affect Firefox ESR 24.3 and Firefox 27. (CVE-2014-1493)

 *

 Gregor Wagner, Olli Pettay, Gary Kwong, Jesse Ruderman, Luke Wagner, Rob Fletcher, and Makoto Kato reported memory safety problems and crashes that affect Firefox 27. (CVE-2014-1494)

 *

 MFSA 2014-16 / CVE-2014-1496: Security researcher Ash reported an issue where the extracted files for updates to existing files are not read only during the update process.
This allows for the potential replacement or modification of these files during the update process if a malicious application is present on the local system.

 *

 MFSA 2014-17 / CVE-2014-1497: Security researcher Atte Kettunen from OUSPG reported an out of bounds read during the decoding of WAV format audio files for playback.
This could allow web content access to heap data as well as causing a crash.

 *

 MFSA 2014-18 / CVE-2014-1498: Mozilla developer David Keeler reported that the crypto.generateCRFMRequest method did not correctly validate the key type of the KeyParams argument when generating ec-dual-use requests. This could lead to a crash and a denial of service (DOS) attack.

 *

 MFSA 2014-19 / CVE-2014-1499: Mozilla developer Ehsan Akhgari reported a spoofing attack where the permission prompt for a WebRTC session can appear to be from a different site than its actual originating site if a timed navigation occurs during the prompt generation. This allows an attacker to potentially gain access to the webcam or microphone by masquerading as another site and gaining user permission through spoofing.

 *

 MFSA 2014-20 / CVE-2014-1500: Security researchers Tim Philipp Schaefers and Sebastian Neef, the team of Internetwache.org, reported a mechanism using JavaScript onbeforeunload events with page navigation to prevent users from closing a malicious page's tab and causing the browser to become unresponsive. This allows for a denial of service
(DOS) attack due to resource consumption and blocks the ability of users to exit the application.

 *

 MFSA 2014-21 / CVE-2014-1501: Security researcher Alex Infuehr reported that on Firefox for Android it is possible to open links to local files from web content by selecting 'Open Link in New Tab' from the context menu using the file: protocol. The web content would have to know the precise location ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.4.0esr~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~24~0.7.23", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~24.4.0esr~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.10.4~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.10.4~0.3.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-x86", rpm:"mozilla-nspr-x86~4.10.4~0.3.1", rls:"SLES11.0SP3"))) {
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

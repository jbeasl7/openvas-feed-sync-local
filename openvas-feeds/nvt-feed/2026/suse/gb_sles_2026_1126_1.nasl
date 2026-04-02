# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1126.1");
  script_cve_id("CVE-2025-59375", "CVE-2026-4684", "CVE-2026-4685", "CVE-2026-4686", "CVE-2026-4687", "CVE-2026-4688", "CVE-2026-4689", "CVE-2026-4690", "CVE-2026-4691", "CVE-2026-4692", "CVE-2026-4693", "CVE-2026-4694", "CVE-2026-4695", "CVE-2026-4696", "CVE-2026-4697", "CVE-2026-4698", "CVE-2026-4699", "CVE-2026-4700", "CVE-2026-4701", "CVE-2026-4702", "CVE-2026-4704", "CVE-2026-4705", "CVE-2026-4706", "CVE-2026-4707", "CVE-2026-4708", "CVE-2026-4709", "CVE-2026-4710", "CVE-2026-4711", "CVE-2026-4712", "CVE-2026-4713", "CVE-2026-4714", "CVE-2026-4715", "CVE-2026-4716", "CVE-2026-4717", "CVE-2026-4718", "CVE-2026-4719", "CVE-2026-4720", "CVE-2026-4721");
  script_tag(name:"creation_date", value:"2026-03-30 04:58:33 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 15:29:55 +0000 (Wed, 25 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1126-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261126-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260083");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/025023.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2026:1126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Update to Firefox 140.9.0 ESR (MFSA 2026-22, bsc#1260083):

 - CVE-2026-4684: Race condition, use-after-free in the Graphics: WebRender component
 - CVE-2026-4685: Incorrect boundary conditions in the Graphics: Canvas2D component
 - CVE-2026-4686: Incorrect boundary conditions in the Graphics: Canvas2D component
 - CVE-2026-4687: Sandbox escape due to incorrect boundary conditions in the Telemetry component
 - CVE-2026-4688: Sandbox escape due to use-after-free in the Disability Access APIs component
 - CVE-2026-4689: Sandbox escape due to incorrect boundary conditions, integer overflow in the XPCOM component
 - CVE-2026-4690: Sandbox escape due to incorrect boundary conditions, integer overflow in the XPCOM component
 - CVE-2026-4691: Use-after-free in the CSS Parsing and Computation component
 - CVE-2026-4692: Sandbox escape in the Responsive Design Mode component
 - CVE-2026-4693: Incorrect boundary conditions in the Audio/Video: Playback component
 - CVE-2026-4694: Incorrect boundary conditions, integer overflow in the Graphics component
 - CVE-2026-4695: Incorrect boundary conditions in the Audio/Video: Web Codecs component
 - CVE-2026-4696: Use-after-free in the Layout: Text and Fonts component
 - CVE-2026-4697: Incorrect boundary conditions in the Audio/Video: Web Codecs component
 - CVE-2026-4698: JIT miscompilation in the JavaScript Engine: JIT component
 - CVE-2026-4699: Incorrect boundary conditions in the Layout: Text and Fonts component
 - CVE-2026-4700: Mitigation bypass in the Networking: HTTP component
 - CVE-2026-4701: Use-after-free in the JavaScript Engine component
 - CVE-2026-4702: JIT miscompilation in the JavaScript Engine component
 - CVE-2026-4704: Denial-of-service in the WebRTC: Signaling component
 - CVE-2026-4705: Undefined behavior in the WebRTC: Signaling component
 - CVE-2026-4706: Incorrect boundary conditions in the Graphics: Canvas2D component
 - CVE-2026-4707: Incorrect boundary conditions in the Graphics: Canvas2D component
 - CVE-2026-4708: Incorrect boundary conditions in the Graphics component
 - CVE-2026-4709: Incorrect boundary conditions in the Audio/Video: GMP component
 - CVE-2026-4710: Incorrect boundary conditions in the Audio/Video component
 - CVE-2026-4711: Use-after-free in the Widget: Cocoa component
 - CVE-2026-4712: Information disclosure in the Widget: Cocoa component
 - CVE-2026-4713: Incorrect boundary conditions in the Graphics component
 - CVE-2026-4714: Incorrect boundary conditions in the Audio/Video component
 - CVE-2026-4715: Uninitialized memory in the Graphics: Canvas2D component
 - CVE-2026-4716: Incorrect boundary conditions, uninitialized memory in the JavaScript Engine component
 - CVE-2026-4717: Privilege escalation in the Netmonitor component
 - CVE-2025-59375: Denial-of-service in the XML component
 - CVE-2026-4718: Undefined behavior in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.9.0~150200.152.225.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.9.0~150200.152.225.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.9.0~150200.152.225.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.9.0~150200.152.225.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.9.0~150200.152.225.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.9.0~150200.152.225.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.9.0~150200.152.225.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.9.0~150200.152.225.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.9.0~150200.152.225.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.9.0~150200.152.225.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.9.0~150200.152.225.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.9.0~150200.152.225.1", rls:"SLES15.0SP6"))) {
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

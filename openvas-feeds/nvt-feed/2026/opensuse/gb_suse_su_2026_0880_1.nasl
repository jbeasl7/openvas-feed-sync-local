# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0880.1");
  script_cve_id("CVE-2026-2757", "CVE-2026-2758", "CVE-2026-2759", "CVE-2026-2760", "CVE-2026-2761", "CVE-2026-2762", "CVE-2026-2763", "CVE-2026-2764", "CVE-2026-2765", "CVE-2026-2766", "CVE-2026-2767", "CVE-2026-2768", "CVE-2026-2769", "CVE-2026-2770", "CVE-2026-2771", "CVE-2026-2772", "CVE-2026-2773", "CVE-2026-2774", "CVE-2026-2775", "CVE-2026-2776", "CVE-2026-2777", "CVE-2026-2778", "CVE-2026-2779", "CVE-2026-2780", "CVE-2026-2781", "CVE-2026-2782", "CVE-2026-2783", "CVE-2026-2784", "CVE-2026-2785", "CVE-2026-2786", "CVE-2026-2787", "CVE-2026-2788", "CVE-2026-2789", "CVE-2026-2790", "CVE-2026-2791", "CVE-2026-2792", "CVE-2026-2793");
  script_tag(name:"creation_date", value:"2026-03-16 04:54:03 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 16:02:24 +0000 (Wed, 25 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0880-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0880-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260880-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258568");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024685.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2026:0880-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Mozilla Thunderbird 140.8 MFSA 2026-17 (bsc#1258568):

- CVE-2026-2757: Incorrect boundary conditions in the WebRTC: Audio/Video
 component
- CVE-2026-2758: Use-after-free in the JavaScript: GC component
- CVE-2026-2759: Incorrect boundary conditions in the Graphics: ImageLib
 component
- CVE-2026-2760: Sandbox escape due to incorrect boundary conditions in the
 Graphics: WebRender component
- CVE-2026-2761: Sandbox escape in the Graphics: WebRender component
- CVE-2026-2762: Integer overflow in the JavaScript: Standard Library component
- CVE-2026-2763: Use-after-free in the JavaScript Engine component
- CVE-2026-2764: JIT miscompilation, use-after-free in the JavaScript Engine:
 JIT component
- CVE-2026-2765: Use-after-free in the JavaScript Engine component
- CVE-2026-2766: Use-after-free in the JavaScript Engine: JIT component
- CVE-2026-2767: Use-after-free in the JavaScript: WebAssembly component
- CVE-2026-2768: Sandbox escape in the Storage: IndexedDB component
- CVE-2026-2769: Use-after-free in the Storage: IndexedDB component
- CVE-2026-2770: Use-after-free in the DOM: Bindings (WebIDL) component
- CVE-2026-2771: Undefined behavior in the DOM: Core & HTML component
- CVE-2026-2772: Use-after-free in the Audio/Video: Playback component
- CVE-2026-2773: Incorrect boundary conditions in the Web Audio component
- CVE-2026-2774: Integer overflow in the Audio/Video component
- CVE-2026-2775: Mitigation bypass in the DOM: HTML Parser component
- CVE-2026-2776: Sandbox escape due to incorrect boundary conditions in the
 Telemetry component in External Software
- CVE-2026-2777: Privilege escalation in the Messaging System component
- CVE-2026-2778: Sandbox escape due to incorrect boundary conditions in the
 DOM: Core & HTML component
- CVE-2026-2779: Incorrect boundary conditions in the Networking: JAR component
- CVE-2026-2780: Privilege escalation in the Netmonitor component
- CVE-2026-2781: Integer overflow in the Libraries component in NSS
- CVE-2026-2782: Privilege escalation in the Netmonitor component
- CVE-2026-2783: Information disclosure due to JIT miscompilation in the
 JavaScript Engine: JIT component
- CVE-2026-2784: Mitigation bypass in the DOM: Security component
- CVE-2026-2785: Invalid pointer in the JavaScript Engine component
- CVE-2026-2786: Use-after-free in the JavaScript Engine component
- CVE-2026-2787: Use-after-free in the DOM: Window and Location component
- CVE-2026-2788: Incorrect boundary conditions in the Audio/Video: GMP
 component
- CVE-2026-2789: Use-after-free in the Graphics: ImageLib component
- CVE-2026-2790: Same-origin policy bypass in the Networking: JAR component
- CVE-2026-2791: Mitigation bypass in the Networking: Cache component
- CVE-2026-2792: Memory safety bugs fixed in Firefox ESR 140.8, Thunderbird ESR
 140.8, Firefox 148 and Thunderbird 148
- CVE-2026-2793: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~140.8.0~150200.8.260.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~140.8.0~150200.8.260.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~140.8.0~150200.8.260.1", rls:"openSUSELeap15.6"))) {
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

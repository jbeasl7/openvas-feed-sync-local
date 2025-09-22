# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833735");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:15:08 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for tor (openSUSE-SU-2023:0361-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0361-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6CUKHNCCOEC5HWMHMSYJY6GFFOSP2ZIL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor'
  package(s) announced via the openSUSE-SU-2023:0361-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tor fixes the following issues:

  - tor 0.4.8.8:

  * Mitigate an issue when Tor compiled with OpenSSL can crash during
         handshake with a remote relay. (TROVE-2023-004, boo#1216873)

  * Regenerate fallback directories generated on November 03, 2023.

  * Update the geoip files to match the IPFire Location Database, as
         retrieved on 2023/11/03

  * directory authority: Look at the network parameter 'maxunmeasuredbw'
         with the correct spelling

  * vanguards addon support: Count the conflux linked cell as valid when
         it is successfully processed. This will quiet a spurious warn in the
         vanguards addon

  - tor 0.4.8.7:

  * Fix an issue that prevented us from pre-building more conflux sets
         after existing sets had been used

  - tor 0.4.8.6:

  * onion service: Fix a reliability issue where services were expiring
         their introduction points every consensus update. This caused
         connectivity issues for clients caching the old descriptor and intro
         points

  * Log the input and output buffer sizes when we detect a potential
         compression bomb

  * Disable multiple BUG warnings of a missing relay identity key when
         starting an instance of Tor compiled without relay support

  * When reporting a pseudo-networkstatus as a bridge authority, or
         answering 'ns/purpose/*' controller requests, include accurate
         published-on dates from our list of router descriptors

  * Use less frightening language and lower the log-level of our run-time
         ABI compatibility check message in our Zstd compression subsystem

  - tor 0.4.8.5:

  * bugfixes creating log BUG stacktrace

  - tor 0.4.8.4:

  * Extend DoS protection to partially opened channels and known relays

  * Dynamic Proof-Of-Work protocol to thwart flooding DoS attacks against
         hidden services. Disabled by default, enable via 'HiddenServicePoW' in
         torrc

  * Implement conflux traffic splitting

  * Directory authorities and relays now interact properly with directory
         authorities if they change addresses

  - tor 0.4.7.14:

  * bugfix affecting vanguards (onion service), and minor fixes

  - Enable support for scrypt()");

  script_tag(name:"affected", value:"'tor' package(s) on openSUSE Backports SLE-15-SP4, openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debuginfo", rpm:"tor-debuginfo~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debugsource", rpm:"tor-debugsource~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debuginfo", rpm:"tor-debuginfo~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor-debugsource", rpm:"tor-debugsource~0.4.8.8~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.8.8~bp154.2.15.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.4.8.8~bp154.2.15.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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

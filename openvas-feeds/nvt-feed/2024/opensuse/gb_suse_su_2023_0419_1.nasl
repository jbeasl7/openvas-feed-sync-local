# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833897");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215", "CVE-2022-35255", "CVE-2022-35256", "CVE-2022-43548");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-08 15:58:51 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:59 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for nodejs18 (SUSE-SU-2023:0419-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0419-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IFINPDPVAMM4CHRNO7C2JPZ73LJTP63B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18'
  package(s) announced via the SUSE-SU-2023:0419-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:

     This update ships nodejs18 (jsc#PED-2097)

     Update to NodejJS 18.13.0 LTS:

  * build: disable v8 snapshot compression by default

  * crypto: update root certificates

  * deps: update ICU to 72.1

  * doc:

       + add doc-only deprecation for headers/trailers setters
       + add Rafael to the tsc
       + deprecate use of invalid ports in url.parse
       + deprecate url.parse()

  * lib: drop fetch experimental warning

  * net: add autoSelectFamily and autoSelectFamilyAttemptTimeout options

  * src:

       + add uvwasi version
       + add initial shadow realm support

  * test_runner:

       + add t.after() hook
       + don't use a symbol for runHook()

  * tls:

       + add 'ca' property to certificate object

  * util:

       + add fast path for utf8 encoding
       + improve textdecoder decode performance
       + add MIME utilities

  - Fixes compatibility with ICU 72.1 (bsc#1205236)

  - Fix migration to openssl-3 (bsc#1205042)

     Update to NodeJS 18.12.1 LTS:

  * inspector: DNS rebinding in --inspect via invalid octal IP (bsc#1205119,
       CVE-2022-43548)

     Update to NodeJS 18.12.0 LTS:

  * Running in 'watch' mode using node --watch restarts the process when an
       imported file is changed.

  * fs: add FileHandle.prototype.readLines

  * http: add writeEarlyHints function to ServerResponse

  * http2: make early hints generic

  * util: add default value option to parsearg

     Update to NodeJS 18.11.0:

  * added experimental watch mode -- running in 'watch' mode using node

  - -watch restarts the process when an imported file is changed

  * fs: add FileHandle.prototype.readLines

  * http: add writeEarlyHints function to ServerResponse

  * http2: make early hints generic

  * lib: refactor transferable AbortSignal

  * src: add detailed embedder process initialization API

  * util: add default value option to parsearg

     Update to NodeJS 18.10.0:

  * deps: upgrade npm to 8.19.2

  * http: throw error on content-length mismatch

  * stream: add ReadableByteStream.tee()

     Update to Nodejs 18.9.1:

  * deps: llhttp updated to 6.0.10

       + CVE-2022-32213 bypass via obs-fold mechanic (bsc#1201325)
       + Incorrect Parsing of Multi-line Transfer-Encoding (CVE-2022-32215,
         bsc#1201327)
       + Incorrect Parsing of Header Fields (CVE-2022-35256, bsc#1203832)

  * crypto: fix weak randomness in WebCrypto keygen (CVE-2022-35255,
       bsc#1203831)

     Update to Nodejs 1 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nodejs18' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.13.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"corepack18", rpm:"corepack18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.13.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
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
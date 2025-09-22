# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851711");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-02-27 08:15:45 +0100 (Tue, 27 Feb 2018)");
  script_cve_id("CVE-2015-9100", "CVE-2015-9101", "CVE-2017-11720", "CVE-2017-13712", "CVE-2017-15019", "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412", "CVE-2017-9869", "CVE-2017-9870", "CVE-2017-9871", "CVE-2017-9872");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 01:29:00 +0000 (Thu, 31 Aug 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for lame (openSUSE-SU-2018:0544-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lame'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lame fixes the following issues:

  Lame was updated to version 3.100:

  * Improved detection of MPEG audio data in RIFF WAVE files. sf#3545112
  Invalid sampling detection

  * New switch --gain  decibel, range -20.0 to +12.0, a more convenient
  way to apply Gain adjustment in decibels, than the use of --scale
   factor.

  * Fix for sf#3558466 Bug in path handling

  * Fix for sf#3567844 problem with Tag genre

  * Fix for sf#3565659 no progress indication with pipe input

  * Fix for sf#3544957 scale (empty) silent encode without warning

  * Fix for sf#3580176 environment variable LAMEOPT doesn't work anymore

  * Fix for sf#3608583 input file name displayed with wrong character
  encoding (on windows console with CP_UTF8)

  * Fix dereference NULL and Buffer not NULL terminated issues.
  (CVE-2017-15019 bsc#1082317 CVE-2017-13712 bsc#1082399 CVE-2015-9100
  bsc#1082401)

  * Fix dereference of a null pointer possible in loop.

  * Make sure functions with SSE instructions maintain their own properly
  aligned stack. Thanks to Fabian Greffrath

  * Multiple Stack and Heap Corruptions from Malicious File.
  (CVE-2017-9872 bsc#1082391 CVE-2017-9871 bsc#1082392 CVE-2017-9870
  bsc#1082393 CVE-2017-9869 bsc#1082395 CVE-2017-9411 bsc#1082397
  CVE-2015-9101 bsc#1082400)

  * CVE-2017-11720: Fix a division by zero vulnerability. (bsc#1082311)

  * CVE-2017-9410: Fix fill_buffer_resample function in libmp3lame/util.c
  heap-based buffer over-read and ap (bsc#1082333)

  * CVE-2017-9411: Fix fill_buffer_resample function in libmp3lame/util.c
  invalid memory read and application crash (bsc#1082397)

  * CVE-2017-9412: FIx unpack_read_samples function in
  frontend/get_audio.c invalid memory read and application crash
  (bsc#1082340)

  * Fix clip detect scale suggestion unaware of scale input value

  * HIP decoder bug fixed: decoding mixed blocks of lower sample frequency
  Layer3 data resulted in internal buffer overflow.

  * Add lame_encode_buffer_interleaved_int()");

  script_tag(name:"affected", value:"lame on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0544-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-02/msg00046.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"lame", rpm:"lame~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lame-debuginfo", rpm:"lame-debuginfo~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lame-debugsource", rpm:"lame-debugsource~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lame-doc", rpm:"lame-doc~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lame-mp3rtp", rpm:"lame-mp3rtp~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lame-mp3rtp-debuginfo", rpm:"lame-mp3rtp-debuginfo~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp3lame-devel", rpm:"libmp3lame-devel~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp3lame0", rpm:"libmp3lame0~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp3lame0-debuginfo", rpm:"libmp3lame0-debuginfo~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp3lame0-32bit", rpm:"libmp3lame0-32bit~3.100~7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmp3lame0-debuginfo-32bit", rpm:"libmp3lame0-debuginfo-32bit~3.100~7.1", rls:"openSUSELeap42.3"))) {
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

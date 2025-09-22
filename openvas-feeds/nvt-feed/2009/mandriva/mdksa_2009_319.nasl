# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66401");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5243", "CVE-2008-5245", "CVE-2008-5246", "CVE-2009-1274", "CVE-2009-0385", "CVE-2009-0698");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:319 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Vulnerabilities have been discovered and corrected in xine-lib:

Failure on Ogg files manipulation can lead remote attackers to cause
a denial of service by using crafted files (CVE-2008-3231).

Failure on manipulation of either MNG or Real or MOD files can lead
remote attackers to cause a denial of service by using crafted files
(CVE: CVE-2008-5233).

Heap-based overflow allows remote attackers to execute arbitrary
code by using Quicktime media files holding crafted metadata
(CVE-2008-5234).

Heap-based overflow allows remote attackers to execute arbitrary code
by using either crafted Matroska or Real media files (CVE-2008-5236).

Failure on manipulation of either MNG or Quicktime files can lead
remote attackers to cause a denial of service by using crafted files
(CVE-2008-5237).

Multiple heap-based overflow on input plugins (http, net, smb, dvd,
dvb, rtsp, rtp, pvr, pnm, file, gnome_vfs, mms) allow attackers to
execute arbitrary code by handling that input channels. Further
this problem can even lead attackers to cause denial of service
(CVE-2008-5239).

Heap-based overflow allows attackers to execute arbitrary code by using
crafted Matroska media files (MATROSKA_ID_TR_CODECPRIVATE track entry
element). Further a failure on handling of Real media files (CONT_TAG
header) can lead to a denial of service attack (CVE-2008-5240).

Integer underflow allows remote attackers to cause denial of service
by using Quicktime media files (CVE-2008-5241).

Failure on manipulation of Real media files can lead remote attackers
to cause a denial of service by indexing an allocated buffer with a
certain input value in a crafted file (CVE-2008-5243).

Vulnerabilities of unknown impact - possibly buffer overflow - caused
by a condition of video frame preallocation before ascertaining the
required length in V4L video input plugin (CVE-2008-5245).

Heap-based overflow allows remote attackers to execute arbitrary
code by using crafted media files. This vulnerability is in the
manipulation of ID3 audio file data tagging mainly used in MP3 file
formats (CVE-2008-5246).

Integer overflow in the qt_error parse_trak_atom function in
demuxers/demux_qt.c in xine-lib 1.1.16.2 and earlier allows remote
attackers to execute arbitrary code via a Quicktime movie file with a
large count value in an STTS atom, which triggers a heap-based buffer
overflow (CVE-2009-1274)

Integer overflow in the 4xm demuxer (demuxers/demux_4xm.c) in xine-lib
1.1.16.1 allows remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via a 4X movie file with a large
current_track value, a similar issue to CVE-2009-0385 (CVE-2009-0698)

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update fixes these issues.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:319");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory MDVSA-2009:319.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxine1", rpm:"libxine1~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxine-devel", rpm:"libxine-devel~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-aa", rpm:"xine-aa~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-caca", rpm:"xine-caca~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-dxr3", rpm:"xine-dxr3~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-esd", rpm:"xine-esd~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-flac", rpm:"xine-flac~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-gnomevfs", rpm:"xine-gnomevfs~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-image", rpm:"xine-image~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-jack", rpm:"xine-jack~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-plugins", rpm:"xine-plugins~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-pulse", rpm:"xine-pulse~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-sdl", rpm:"xine-sdl~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-smb", rpm:"xine-smb~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine1", rpm:"lib64xine1~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xine-devel", rpm:"lib64xine-devel~1.1.8~4.8mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}

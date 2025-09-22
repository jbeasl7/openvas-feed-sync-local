# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892962");
  script_cve_id("CVE-2021-32686", "CVE-2021-37706", "CVE-2021-41141", "CVE-2021-43299", "CVE-2021-43300", "CVE-2021-43301", "CVE-2021-43302", "CVE-2021-43303", "CVE-2021-43804", "CVE-2021-43845", "CVE-2022-21722", "CVE-2022-21723", "CVE-2022-23608", "CVE-2022-24754", "CVE-2022-24764");
  script_tag(name:"creation_date", value:"2022-03-29 01:00:21 +0000 (Tue, 29 Mar 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-23 12:56:25 +0000 (Wed, 23 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2962-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2962-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2962-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/pjproject");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pjproject' package(s) announced via the DLA-2962-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in pjproject, is a free and open source multimedia communication library.

CVE-2021-32686

A race condition between callback and destroy, due to the accepted socket having no group lock. Second, the SSL socket parent/listener may get destroyed during handshake. s. They cause crash, resulting in a denial of service.

CVE-2021-37706

An incoming STUN message contains an ERROR-CODE attribute, the header length is not checked before performing a subtraction operation, potentially resulting in an integer underflow scenario. This issue affects all users that use STUN. A malicious actor located within the victim's network may forge and send a specially crafted UDP (STUN) message that could remotely execute arbitrary code on the victim's machine

CVE-2021-41141

In various parts of PJSIP, when error/failure occurs, it is found that the function returns without releasing the currently held locks. This could result in a system deadlock, which cause a denial of service for the users.

CVE-2021-43299

Stack overflow in PJSUA API when calling pjsua_player_create. An attacker-controlled filename argument may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size validation.

CVE-2021-43300

Stack overflow in PJSUA API when calling pjsua_recorder_create. An attacker-controlled filename argument may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size validation.

CVE-2021-43301

Stack overflow in PJSUA API when calling pjsua_playlist_create. An attacker-controlled file_names argument may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size validation.

CVE-2021-43302

Read out-of-bounds in PJSUA API when calling pjsua_recorder_create. An attacker-controlled filename argument may cause an out-of-bounds read when the filename is shorter than 4 characters.

CVE-2021-43303

Buffer overflow in PJSUA API when calling pjsua_call_dump. An attacker-controlled buffer argument may cause a buffer overflow, since supplying an output buffer smaller than 128 characters may overflow the output buffer, regardless of the maxlen argument supplied

CVE-2021-43804

An incoming RTCP BYE message contains a reason's length, this declared length is not checked against the actual received packet size, potentially resulting in an out-of-bound read access. A malicious actor can send a RTCP BYE message with an invalid reason length

CVE-2021-43845

if incoming RTCP XR message contain block, the data field is not checked against the received packet size, potentially resulting in an out-of-bound read access

CVE-2022-21722

it is possible that certain incoming RTP/RTCP packets can potentially cause out-of-bound read access. This issue affects all users that use PJMEDIA and accept incoming RTP/RTCP.

CVE-2022-21723

Parsing an incoming SIP message that contains a malformed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pjproject' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libpj2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjlib-util2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-audiodev2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-codec2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia-videodev2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjmedia2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjnath2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjproject-dev", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsip-simple2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsip-ua2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsip2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsua2", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpjsua2-2v5", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pjproject", ver:"2.5.5~dfsg-6+deb9u3", rls:"DEB9"))) {
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

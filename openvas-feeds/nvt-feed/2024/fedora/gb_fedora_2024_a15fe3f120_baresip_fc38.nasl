# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886232");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:36:38 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for baresip (FEDORA-2024-a15fe3f120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a15fe3f120");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GP6TNQ7Y7OSEAVMOUPEQAKZTUHZ45GV6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'baresip'
  package(s) announced via the FEDORA-2024-a15fe3f120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A modular SIP user-agent with support for audio and video, and many IETF
standards such as SIP, SDP, RTP/RTCP and STUN/TURN/ICE for both, IPv4 and
IPv6.

Additional modules provide support for audio codecs like Codec2, G.711,
G.722, G.726, GSM, L16, MPA and Opus, audio drivers like ALSA, GStreamer,
JACK Audio Connection Kit, Portaudio, and PulseAudio, video codecs like
AV1, VP8 or VP9, video sources like Video4Linux, video outputs like SDL2
or X11, NAT traversal via STUN, TURN, ICE, and NAT-PMP, media encryption
via TLS, SRTP or DTLS-SRTP, management features like embedded web-server
with HTTP interface, command-line console and interface, and MQTT.");

  script_tag(name:"affected", value:"'baresip' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"baresip", rpm:"baresip~3.10.1~1.fc38", rls:"FC38"))) {
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

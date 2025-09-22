# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886320");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:39:02 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for libre (FEDORA-2024-a63e807450)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a63e807450");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UHU4A2TTFU36LOVBMFX2XZCMODVX2JPV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libre'
  package(s) announced via the FEDORA-2024-a63e807450 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libre is a generic library for real-time communications with async I/O
support. Features are a SIP stack (RFC 3261), SDP, RTP and RTCP, SRTP and
SRTCP (Secure RTP), DNS client, STUN/TURN/ICE stack, BFCP, HTTP stack with
client/server, Websockets, Jitter buffer, async I/O (poll, epoll, select,
kqueue), UDP/TCP/TLS/DTLS transport, JSON parser and Real Time Messaging
Protocol (RTMP).");

  script_tag(name:"affected", value:"'libre' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

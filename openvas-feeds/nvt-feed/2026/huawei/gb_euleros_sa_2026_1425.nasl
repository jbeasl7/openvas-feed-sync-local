# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1425");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-14512", "CVE-2025-3360", "CVE-2025-4373", "CVE-2025-7039", "CVE-2026-0988");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-06 17:19:39 +0000 (Fri, 06 Feb 2026)");

  script_name("Huawei EulerOS: Security Advisory for glib2 (EulerOS-SA-2026-1425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1425");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1425");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'glib2' package(s) announced via the EulerOS-SA-2026-1425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in glib. Missing validation of offset and count parameters in the g_buffered_input_stream_peek() function can lead to an integer overflow during length calculation. When specially crafted values are provided, this overflow results in an incorrect size being passed to memcpy(), triggering a buffer overflow. This can cause application crashes, leading to a Denial of Service (DoS).(CVE-2026-0988)

A flaw was found in glib. This vulnerability allows a heap buffer overflow and denial-of-service (DoS) via an integer overflow in GLib's GIO (GLib Input/Output) escape_byte_string() function when processing malicious file or remote filesystem attribute values.(CVE-2025-14512)

A heap-based buffer overflow problem was found in glib through an incorrect calculation of buffer size in the g_escape_uri_string() function. If the string to escape contains a very large number of unacceptable characters (which would need escaping), the calculation of the length of the escaped string could overflow, leading to a potential write off the end of the newly allocated string.(CVE-2025-13601)

A flaw was found in GLib (Gnome Lib). This vulnerability allows a remote attacker to cause heap corruption, leading to a denial of service or potential code execution via a buffer-underflow in the GVariant parser when processing maliciously crafted input strings.(CVE-2025-14087)

A flaw was found in glib. An integer overflow during temporary file creation leads to an out-of-bounds memory access, allowing an attacker to potentially perform path traversal or access private temporary file content by creating symbolic links. This vulnerability allows a local attacker to manipulate file paths and access unauthorized data. The core issue stems from insufficient validation of file path lengths during temporary file operations.(CVE-2025-7039)

A flaw was found in GLib, which is vulnerable to an integer overflow in the g_string_insert_unichar() function. When the position at which to insert the character is large, the position will overflow, leading to a buffer underwrite.(CVE-2025-4373)

A flaw was found in GLib. An integer overflow and buffer under-read occur when parsing a long invalid ISO 8601 timestamp with the g_date_time_new_from_iso8601() function.(CVE-2025-3360)");

  script_tag(name:"affected", value:"'glib2' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"glib2", rpm:"glib2~2.72.2~5.h27.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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

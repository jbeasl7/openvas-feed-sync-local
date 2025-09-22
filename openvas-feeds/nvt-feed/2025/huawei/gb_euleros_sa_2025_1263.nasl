# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1263");
  script_cve_id("CVE-2024-47538", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47600", "CVE-2024-47607", "CVE-2024-47615", "CVE-2024-47835");
  script_tag(name:"creation_date", value:"2025-03-17 15:44:41 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:57:16 +0000 (Wed, 18 Dec 2024)");

  script_name("Huawei EulerOS: Security Advisory for gstreamer1-plugins-base (EulerOS-SA-2025-1263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1263");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1263");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gstreamer1-plugins-base' package(s) announced via the EulerOS-SA-2025-1263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer is a library for constructing graphs of media-handling components. A null pointer dereference has been discovered in the id3v2_read_synch_uint function, located in id3v2.c. If id3v2_read_synch_uint is called with a null work->hdr.frame_data, the pointer guint8 *data is accessed without validation, resulting in a null pointer dereference. This vulnerability can result in a Denial of Service (DoS) by triggering a segmentation fault (SEGV). This vulnerability is fixed in 1.24.10.(CVE-2024-47542)

GStreamer is a library for constructing graphs of media-handling components. stack-buffer overflow has been detected in the gst_opus_dec_parse_header function within `gstopusdec.c'. The pos array is a stack-allocated buffer of size 64. If n_channels exceeds 64, the for loop will write beyond the boundaries of the pos array. The value written will always be GST_AUDIO_CHANNEL_POSITION_NONE. This bug allows to overwrite the EIP address allocated in the stack. This vulnerability is fixed in 1.24.10.(CVE-2024-47607)

GStreamer is a library for constructing graphs of media-handling components. An OOB-read vulnerability has been detected in the format_channel_mask function in gst-discoverer.c. The vulnerability affects the local array position, which is defined with a fixed size of 64 elements. However, the function gst_discoverer_audio_info_get_channels may return a guint channels value greater than 64. This causes the for loop to attempt access beyond the bounds of the position array, resulting in an OOB-read when an index greater than 63 is used. This vulnerability can result in reading unintended bytes from the stack. Additionally, the dereference of value->value_nick after the OOB-read can lead to further memory corruption or undefined behavior. This vulnerability is fixed in 1.24.10.(CVE-2024-47600)

GStreamer is a library for constructing graphs of media-handling components. An OOB-write vulnerability has been identified in the gst_ssa_parse_remove_override_codes function of the gstssaparse.c file. This function is responsible for parsing and removing SSA (SubStation Alpha) style override codes, which are enclosed in curly brackets ({}). The issue arises when a closing curly bracket '}' appears before an opening curly bracket '{' in the input string. In this case, memmove() incorrectly duplicates a substring. With each successive loop iteration, the size passed to memmove() becomes progressively larger (strlen(end+1)), leading to a write beyond the allocated memory bounds. This vulnerability is fixed in 1.24.10.(CVE-2024-47541)

GStreamer is a library for constructing graphs of media-handling components. An OOB-Write has been detected in the function gst_parse_vorbis_setup_packet within vorbis_parse.c. The integer size is read from the input file without proper validation. As a result, size can exceed the fixed size of the pad->vorbis_mode_sizes array (which size is 256). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gstreamer1-plugins-base' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base", rpm:"gstreamer1-plugins-base~1.14.4~3.h4.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-base-help", rpm:"gstreamer1-plugins-base-help~1.14.4~3.h4.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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

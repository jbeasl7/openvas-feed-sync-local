# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-823g_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170506");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-07-05 09:32:27 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-17 04:15:16 +0000 (Mon, 17 Mar 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2023-26612",
                "CVE-2023-26613",
                "CVE-2023-26615",
                "CVE-2023-26616",
                "CVE-2024-13030",
                "CVE-2024-27655",
                "CVE-2024-27656",
                "CVE-2024-27657",
                "CVE-2024-27658",
                "CVE-2024-27659",
                "CVE-2024-27660",
                "CVE-2024-27661",
                "CVE-2024-27662",
                "CVE-2024-33345",
                "CVE-2024-51023",
                "CVE-2024-51024",
                "CVE-2025-2359",
                "CVE-2025-2360");

  script_name("D-Link DIR-823G Multiple Vulnerabilities (2023-2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-823G devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-26612: Buffer overflow originating from the HostName field in SetParentsControlInfo

  - CVE-2023-26613: OS command injection via a crafted get request to EXCU_SHELL

  - CVE-2023-26615: Web page management password reset via SetMultipleActions API

  - CVE-2023-26616: Buffer overflow originating from the URL field in SetParentsControlInfo

  - CVE-2024-13030: Improper access controls in the Web Management Interface component

  - CVE-2024-27655: Buffer overflow via the SOAPACTION parameter

  - CVE-2024-27656: Buffer overflow via the Cookie parameter

  - CVE-2024-27657: Buffer overflow via the User-Agent parameter

  - CVE-2024-27658, CVE-2024-27659, CVE-2024-27660, CVE-2024-27661, CVE-2024-27662: NULL-pointer
  dereferences

  - CVE-2024-33345: Null-pointer dereference in the main function of upload_firmware.cgi, which
  allows remote attackers to cause a Denial of Service (DoS) via a crafted input

  - CVE-2024-51023: Command injection via the Address parameter in the SetNetworkTomographySettings
  function

  - CVE-2024-51024: Command injection via the HostName parameter in the SetWanSettings function

  - CVE-2025-2359: Improper authorization by manipulating the SOAPAction argument of the
  SetDDNSSettings function of the file /HNAP1/ of the component DDNS Service

  - CVE-2025-2360: Improper authorization by manipulating the SOAPAction argument of the
  SetUpnpSettings function of the file /HNAP1/ of the component UPnP Service");

  script_tag(name:"affected", value:"D-Link DIR-823G devices in all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.

  Note: Vendor states that DIR-823G reached its End-of-Support Date in 10.02.2020, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/HNAP1/SetMultipleActions");
  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/HNAP1/SetParentsControlInfo");
  script_xref(name:"URL", value:"https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/excu_shell");
  script_xref(name:"URL", value:"https://github.com/n0wstr/IOTVuln/tree/main/DIR-823g/UploadFirmware");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/Unauthorized_Vulnerability/D-Link/DIR-823G/SetAutoRebootSettings.md");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-823G-SetDDNSSettings-1ac53a41781f80d98649dd3cbe106e9b?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-823G-SetDDNSSettings-1ac53a41781f80d98649dd3cbe106e9b?pvs=4");
  script_xref(name:"URL", value:"https://calm-healer-839.notion.site/CVE-APPLY-2024-02-06-b7ed92427c0146469b561bc5d0c4ad4f");
  script_xref(name:"URL", value:"http://www.dlink.com.cn/techsupport/ProductInfo.aspx?m=DIR-823G");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10410");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

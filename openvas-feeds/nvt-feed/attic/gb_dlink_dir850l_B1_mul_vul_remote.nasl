# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107243");
  script_version("2025-03-19T05:38:35+0000");
  script_cve_id("CVE-2017-14417", "CVE-2017-14418");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 20:57:00 +0000 (Wed, 08 Nov 2023)");
  script_name("D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html");

  script_tag(name:"summary", value:"D-Link 850L Firmware B1 is vulnerable to an admin password
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP POST requests and checks the response.");

  script_tag(name:"insight", value:"The webpage ip_of_router/register_send.php doesn't check the
  authentication of the user, thus an attacker can abuse this webpage to gain control of the device.
  This webpage is used to register the device to the myDlink cloud infrastructure.");

  script_tag(name:"impact", value:"Remote attacker can retrieve the admin password and gain full
  access.");

  script_tag(name:"affected", value:"D-Link DIR 850L Rev B1 devices are known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # We shouldn't create user accounts on remote devices...

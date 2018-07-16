#!/bin/bash
#
#

echo "[*] Updating CentOS via yum update:"
yum update -y
echo "[*] Exposing docker daemon port:" 
mkdir /etc/systemd/system/docker.service.d
sh -c "echo '[Service]' >> /etc/systemd/system/docker.service.d/override.conf"
sh -c "echo 'ExecStart=' >> /etc/systemd/system/docker.service.d/override.conf"
sh -c "echo 'ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2376' >> /etc/systemd/system/docker.service.d/override.conf"   
systemctl enable --now docker.service
echo "[*] Restarting docker:" 
systemctl stop docker
systemctl start docker
echo "[*] Downloading huskyci docker images:"
curl -X POST http://localhost:2376/v1.24/images/create?fromImage=huskyci/enry 
curl -X POST http://localhost:2376/v1.24/images/create?fromImage=huskyci/gas 
